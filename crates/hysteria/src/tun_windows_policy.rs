use std::{io, path::Path};
use wfp::{
    ActionType, AppIdConditionBuilder, FilterBuilder, FilterEngine, FilterEngineBuilder,
    FilterWeight, Layer, PortConditionBuilder, ProtocolConditionBuilder, SubLayerBuilder,
    Transaction, WeightRange, interface_index_condition,
};

const FILTER_NAME: &str = "Hysteria TUN";

pub(super) struct PolicyFilters {
    _engine: FilterEngine,
}

impl PolicyFilters {
    pub(super) fn install(interface_index: u32) -> io::Result<Self> {
        let mut engine = FilterEngineBuilder::default().dynamic().open()?;
        let transaction = Transaction::new(&mut engine)?;
        let sublayer = random_guid()?;
        SubLayerBuilder::default()
            .name(FILTER_NAME)
            .description("TUN strict-route filters")
            .weight(u16::MAX)
            .guid(sublayer)
            .add(&transaction)?;

        let executable = std::env::current_exe()?;
        let application = AppIdConditionBuilder::default()
            .equal(Path::new(&executable))?
            .build();
        let tunnel = interface_index_condition(interface_index);
        let udp = ProtocolConditionBuilder::udp().build();
        let dns = PortConditionBuilder::remote().equal(53).build();

        for (layer, family) in [(Layer::ConnectV4, "IPv4"), (Layer::ConnectV6, "IPv6")] {
            FilterBuilder::default()
                .name(format!("{FILTER_NAME} protect {family}"))
                .description("Permit the Hysteria process outside the tunnel")
                .action(ActionType::Permit)
                .layer(layer)
                .sublayer(sublayer)
                .weight(filter_weight(13)?)
                .clear_action_right()
                .condition(application.clone())
                .add(&transaction)?;
            FilterBuilder::default()
                .name(format!("{FILTER_NAME} allow {family}"))
                .description("Permit connections routed through the TUN interface")
                .action(ActionType::Permit)
                .layer(layer)
                .sublayer(sublayer)
                .weight(filter_weight(11)?)
                .condition(tunnel.clone())
                .add(&transaction)?;
            FilterBuilder::default()
                .name(format!("{FILTER_NAME} block {family} DNS"))
                .description("Prevent UDP DNS from bypassing the TUN interface")
                .action(ActionType::Block)
                .layer(layer)
                .sublayer(sublayer)
                .weight(filter_weight(10)?)
                .condition(udp.clone())
                .condition(dns.clone())
                .add(&transaction)?;
        }

        transaction.commit()?;
        Ok(Self { _engine: engine })
    }
}

fn filter_weight(value: u8) -> io::Result<FilterWeight> {
    WeightRange::try_from(value)
        .map(FilterWeight::Range)
        .map_err(io::Error::other)
}

fn random_guid() -> io::Result<wfp::GUID> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| io::Error::other(error.to_string()))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(wfp::GUID::from_u128(u128::from_be_bytes(bytes)))
}
