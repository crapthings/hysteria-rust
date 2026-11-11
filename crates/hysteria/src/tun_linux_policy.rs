use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage,
    NetlinkPayload,
};
use netlink_packet_route::{
    AddressFamily, IpProtocol, RouteNetlinkMessage,
    rule::{RuleAction, RuleAttribute, RuleFlags, RuleHeader, RuleMessage, RulePortRange},
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use std::{
    collections::HashSet,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

const PREFERRED_PRIORITY: u32 = 9_000;
const PRIORITY_BLOCK_SIZE: u32 = 11;
const PRIORITY_SEARCH_END: u32 = 32_000;
const MAIN_TABLE: u8 = 254;

pub(super) struct PolicyRules {
    rules: Vec<RuleMessage>,
}

impl PolicyRules {
    pub(super) fn preflight_routed() -> io::Result<()> {
        validate_routed_environment(&list_rules()?)
    }
    pub(super) fn install_routed(table: u8, mark: u32) -> io::Result<Self> {
        let existing = list_rules()?;
        validate_routed_environment(&existing)?;
        let priority = select_priority(&existing)
            .ok_or_else(|| io::Error::other("no policy priority available"))?;
        let mut installed = Self { rules: Vec::new() };
        for rule in routed_rules(table, priority, mark) {
            add_rule(&rule)?;
            installed.rules.push(rule);
        }
        Ok(installed)
    }
    pub(super) fn install(
        table: u8,
        ipv4_address: (Ipv4Addr, u8),
        ipv6_address: (Ipv6Addr, u8),
    ) -> io::Result<Self> {
        let existing = list_rules()?;
        let priority = select_priority(&existing)
            .ok_or_else(|| io::Error::other("no free policy-rule priority block is available"))?;
        let rules = strict_rules(table, priority, ipv4_address, ipv6_address);
        let mut installed = Self { rules: Vec::new() };
        for rule in rules {
            add_rule(&rule)?;
            installed.rules.push(rule);
        }
        Ok(installed)
    }
}

impl Drop for PolicyRules {
    fn drop(&mut self) {
        for rule in self.rules.iter().rev() {
            if let Err(error) = delete_rule(rule) {
                eprintln!("failed to remove TUN policy rule: {error}");
            }
        }
    }
}

fn validate_routed_environment(existing: &[RuleMessage]) -> io::Result<()> {
    for rule in existing {
        let expected = match rule_priority(rule).unwrap_or(0) {
            0 => 255,
            32766 => 254,
            32767 => 253,
            _ => {
                return Err(io::Error::other(
                    "routed TUN requires standard Linux policy rules; custom rules already exist",
                ));
            }
        };
        if rule.header.table != expected
            || rule.header.action != RuleAction::ToTable
            || !(rule.header.flags & !RuleFlags::Permanent).is_empty()
            || rule.header.src_len != 0
            || rule.header.dst_len != 0
            || rule.attributes.iter().any(|a| {
                !matches!(
                    a,
                    RuleAttribute::Priority(_)
                        | RuleAttribute::Table(_)
                        | RuleAttribute::Protocol(_)
                        | RuleAttribute::SuppressPrefixLen(u32::MAX)
                )
            })
        {
            return Err(io::Error::other(
                "custom Linux policy selectors prevent safe routed TUN installation",
            ));
        }
    }
    Ok(())
}
fn routed_rules(table: u8, priority: u32, mark: u32) -> Vec<RuleMessage> {
    let mut rules = Vec::new();
    for family in [AddressFamily::Inet, AddressFamily::Inet6] {
        let attributes = vec![RuleAttribute::FwMark(mark), RuleAttribute::FwMask(u32::MAX)];
        rules.push(table_rule(
            family,
            priority,
            MAIN_TABLE,
            attributes.clone(),
            0,
        ));
        let mut captured = table_rule(family, priority + 1, table, attributes, 0);
        captured.header.flags = RuleFlags::Invert;
        rules.push(captured);
        let mut stop = base_rule(family, priority + 2, RuleAction::Unreachable);
        stop.header.flags = RuleFlags::Invert;
        stop.attributes
            .extend([RuleAttribute::FwMark(mark), RuleAttribute::FwMask(u32::MAX)]);
        rules.push(stop);
    }
    rules
}

fn strict_rules(
    table: u8,
    priority: u32,
    ipv4_address: (Ipv4Addr, u8),
    _ipv6_address: (Ipv6Addr, u8),
) -> Vec<RuleMessage> {
    let nop_priority = priority + PRIORITY_BLOCK_SIZE - 1;
    vec![
        table_rule(
            AddressFamily::Inet,
            priority,
            table,
            vec![RuleAttribute::Destination(IpAddr::V4(mask_ipv4(
                ipv4_address.0,
                ipv4_address.1,
            )))],
            ipv4_address.1,
        ),
        goto_rule(
            AddressFamily::Inet,
            priority + 1,
            nop_priority,
            IpProtocol::Icmp,
        ),
        dns_main_rule(AddressFamily::Inet, priority + 2),
        table_rule(AddressFamily::Inet, priority + 2, table, vec![], 0),
        goto_rule(
            AddressFamily::Inet6,
            priority,
            nop_priority,
            IpProtocol::Other(58),
        ),
        dns_main_rule(AddressFamily::Inet6, priority + 1),
        table_rule(AddressFamily::Inet6, priority + 1, table, vec![], 0),
        nop_rule(AddressFamily::Inet, nop_priority),
        nop_rule(AddressFamily::Inet6, nop_priority),
    ]
}

fn base_rule(family: AddressFamily, priority: u32, action: RuleAction) -> RuleMessage {
    let mut rule = RuleMessage::default();
    rule.header = RuleHeader {
        family,
        action,
        ..RuleHeader::default()
    };
    rule.attributes.push(RuleAttribute::Priority(priority));
    rule
}

fn table_rule(
    family: AddressFamily,
    priority: u32,
    table: u8,
    mut attributes: Vec<RuleAttribute>,
    destination_prefix: u8,
) -> RuleMessage {
    let mut rule = base_rule(family, priority, RuleAction::ToTable);
    rule.header.table = table;
    rule.header.dst_len = destination_prefix;
    rule.attributes.append(&mut attributes);
    rule.attributes.push(RuleAttribute::Table(u32::from(table)));
    rule
}

fn goto_rule(
    family: AddressFamily,
    priority: u32,
    destination: u32,
    protocol: IpProtocol,
) -> RuleMessage {
    let mut rule = base_rule(family, priority, RuleAction::Goto);
    rule.attributes.extend([
        RuleAttribute::Goto(destination),
        RuleAttribute::IpProtocol(protocol),
    ]);
    rule
}

fn dns_main_rule(family: AddressFamily, priority: u32) -> RuleMessage {
    let mut rule = table_rule(family, priority, MAIN_TABLE, vec![], 0);
    rule.header.flags = RuleFlags::Invert;
    rule.attributes.extend([
        RuleAttribute::DestinationPortRange(RulePortRange { start: 53, end: 53 }),
        RuleAttribute::SuppressPrefixLen(0),
    ]);
    rule
}

fn nop_rule(family: AddressFamily, priority: u32) -> RuleMessage {
    base_rule(family, priority, RuleAction::Nop)
}

fn mask_ipv4(address: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    Ipv4Addr::from(u32::from(address) & mask)
}

fn select_priority(existing: &[RuleMessage]) -> Option<u32> {
    let occupied = existing
        .iter()
        .filter_map(rule_priority)
        .collect::<HashSet<_>>();
    (PREFERRED_PRIORITY..=PRIORITY_SEARCH_END - PRIORITY_BLOCK_SIZE)
        .step_by(PRIORITY_BLOCK_SIZE as usize)
        .find(|start| {
            (*start..*start + PRIORITY_BLOCK_SIZE).all(|priority| !occupied.contains(&priority))
        })
}

fn rule_priority(rule: &RuleMessage) -> Option<u32> {
    rule.attributes
        .iter()
        .find_map(|attribute| match attribute {
            RuleAttribute::Priority(priority) => Some(*priority),
            _ => None,
        })
}

fn list_rules() -> io::Result<Vec<RuleMessage>> {
    let mut rules = Vec::new();
    for family in [AddressFamily::Inet, AddressFamily::Inet6] {
        let mut message = RuleMessage::default();
        message.header.family = family;
        rules.extend(request(
            RouteNetlinkMessage::GetRule(message),
            NLM_F_REQUEST | NLM_F_DUMP,
            true,
        )?);
    }
    Ok(rules)
}

fn add_rule(rule: &RuleMessage) -> io::Result<()> {
    request(
        RouteNetlinkMessage::NewRule(rule.clone()),
        NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
        false,
    )?;
    Ok(())
}

fn delete_rule(rule: &RuleMessage) -> io::Result<()> {
    request(
        RouteNetlinkMessage::DelRule(rule.clone()),
        NLM_F_REQUEST | NLM_F_ACK,
        false,
    )?;
    Ok(())
}

fn request(
    payload: RouteNetlinkMessage,
    flags: u16,
    multipart: bool,
) -> io::Result<Vec<RuleMessage>> {
    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;

    let mut header = NetlinkHeader::default();
    header.flags = flags;
    let mut packet = NetlinkMessage::new(header, NetlinkPayload::from(payload));
    packet.finalize();
    let mut bytes = vec![0; packet.header.length as usize];
    packet.serialize(&mut bytes);
    socket.send(&bytes, 0)?;

    let mut rules = Vec::new();
    loop {
        let mut receive_buffer = vec![0; 16 * 1024];
        let length = socket.recv(&mut &mut receive_buffer[..], 0)?;
        let mut offset = 0;
        while offset < length {
            let message =
                NetlinkMessage::<RouteNetlinkMessage>::deserialize(&receive_buffer[offset..length])
                    .map_err(|error| {
                        io::Error::other(format!("invalid netlink response: {error}"))
                    })?;
            let message_length = message.header.length as usize;
            if message_length == 0 {
                return Err(io::Error::other("zero-length netlink response"));
            }
            match message.payload {
                NetlinkPayload::Done(_) => return Ok(rules),
                NetlinkPayload::Error(error) => {
                    if error.code.is_some() {
                        return Err(error.to_io());
                    }
                    return Ok(rules);
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRule(rule)) => {
                    rules.push(rule);
                }
                _ => {}
            }
            offset += (message_length + 3) & !3;
        }
        if !multipart {
            return Ok(rules);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "read-only policy preflight requires an isolated Linux namespace with default rules"]
    fn routed_policy_read_only_preflight() {
        PolicyRules::preflight_routed().unwrap();
    }
    #[test]
    fn routed_policy_never_captures_marked_egress() {
        let rules = routed_rules(202, 9000, 0x0048_5932);
        assert_eq!(rules.len(), 6);
        for pair in rules.chunks_exact(3) {
            assert_eq!(pair[0].header.table, 254);
            assert_eq!(pair[1].header.table, 202);
            assert!(!pair[0].header.flags.contains(RuleFlags::Invert));
            assert!(pair[1].header.flags.contains(RuleFlags::Invert));
            assert_eq!(pair[2].header.action, RuleAction::Unreachable);
            assert!(pair[2].header.flags.contains(RuleFlags::Invert));
            assert!(
                pair[1]
                    .attributes
                    .contains(&RuleAttribute::FwMark(0x0048_5932))
            );
        }
        let defaults = vec![
            table_rule(AddressFamily::Inet, 0, 255, vec![], 0),
            table_rule(AddressFamily::Inet, 32766, 254, vec![], 0),
        ];
        assert!(validate_routed_environment(&defaults).is_ok());
        assert!(validate_routed_environment(&rules).is_err());
    }
    #[test]
    fn strict_rule_order_matches_sing_tun() {
        let rules = strict_rules(
            202,
            9_000,
            (Ipv4Addr::new(100, 100, 100, 101), 30),
            (Ipv6Addr::LOCALHOST, 126),
        );
        let priorities = rules.iter().map(rule_priority).collect::<Vec<_>>();
        assert_eq!(
            priorities,
            vec![
                Some(9_000),
                Some(9_001),
                Some(9_002),
                Some(9_002),
                Some(9_000),
                Some(9_001),
                Some(9_001),
                Some(9_010),
                Some(9_010),
            ]
        );
        assert_eq!(
            rules[0]
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    RuleAttribute::Destination(address) => Some(*address),
                    _ => None,
                }),
            Some(IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100)))
        );
    }

    #[test]
    fn priority_selection_preserves_existing_rules() {
        let existing = vec![base_rule(
            AddressFamily::Inet,
            PREFERRED_PRIORITY,
            RuleAction::Nop,
        )];
        assert_eq!(select_priority(&existing), Some(9_011));
    }
}
