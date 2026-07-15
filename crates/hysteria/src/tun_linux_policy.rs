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
