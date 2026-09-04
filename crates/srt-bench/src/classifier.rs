//! CLI and result-file surfaces for the pure capacity model.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use crate::harness::{CONFIG_COLUMNS, Record};
use crate::model::{
    AdmissionEnvelope, Availability, BondMode, CapacityAssessment, CapacityInput, CellClass,
    ClassifierPolicy, EncryptionMode, HostEnvelope, NetworkEnvelope, ProtocolEnvelope,
    SrtBandwidthPolicy, WorkloadEnvelope, assess,
};

const OUTPUT_COLUMNS: &[&str] = &[
    "cell",
    "class",
    "reasons",
    "source_pps_total",
    "packet_pps",
    "srt_total_bps",
    "udp_ip_bps",
    "nic_wire_bps",
    "retransmission_factor",
    "bdp_packets",
    "required_window_packets",
    "flow_window_headroom_packets",
    "receive_window_headroom_packets",
    "recovery_margin_ms",
    "socket_horizon_recv_s",
    "socket_horizon_send_s",
    "host_utilization",
    "nic_utilization",
    "admission_waves",
    "policy_rev",
];

#[derive(Clone, Debug)]
struct OutputRow {
    cell: String,
    assessment: CapacityAssessment,
}

/// Run `srt-bench classify`, returning stable text suitable for stdout or a
/// file. A plan is expanded completely; cells are reported, never skipped.
pub fn classify(cli: &crate::Cli) -> Result<String, String> {
    let rows = match cli.flags.get("plan").filter(|value| !value.is_empty()) {
        Some(path) => classify_plan(cli, Path::new(path))?,
        None => vec![OutputRow {
            cell: "explicit".to_string(),
            assessment: assess(
                input_from_cli(cli, &BTreeMap::new())?,
                policy_from_cli(cli)?,
            )
            .map_err(|error| error.0)?,
        }],
    };
    render_rows(&rows, output_format(cli))
}

/// Build the pre-run assessment used in a measured result row. It only uses
/// configuration and explicit policy inputs; effective host observations are
/// intentionally left unknown until the run has happened.
pub fn assessment_for_bench_config(
    cfg: &crate::BenchConfig,
) -> Result<CapacityAssessment, crate::model::ModelError> {
    assess(input_from_bench_config(cfg), ClassifierPolicy::default())
}

fn classify_plan(cli: &crate::Cli, path: &Path) -> Result<Vec<OutputRow>, String> {
    let axes = crate::harness::read_plan(path).map_err(|error| error.to_string())?;
    if axes.iter().any(|(_, values)| values.is_empty()) {
        return Err(format!(
            "{path:?}: every plan axis needs at least one value"
        ));
    }
    let mut cells = vec![BTreeMap::new()];
    for (name, values) in axes {
        let mut next = Vec::with_capacity(cells.len() * values.len());
        for cell in cells {
            for value in &values {
                let mut expanded = cell.clone();
                expanded.insert(name.clone(), value.clone());
                next.push(expanded);
            }
        }
        cells = next;
    }
    cells
        .into_iter()
        .map(|cell| {
            let identity = cell
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join(",");
            let input = input_from_cli(cli, &cell)?;
            let assessment = assess(input, policy_from_cli(cli)?).map_err(|error| error.0)?;
            Ok(OutputRow {
                cell: identity,
                assessment,
            })
        })
        .collect()
}

fn output_format(cli: &crate::Cli) -> &str {
    if cli.flags.contains_key("json") {
        "json"
    } else {
        cli.flags
            .get("format")
            .map(String::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or("table")
    }
}

fn render_rows(rows: &[OutputRow], format: &str) -> Result<String, String> {
    match format {
        "table" => Ok(render_table(rows)),
        "tsv" => Ok(render_tsv(rows)),
        "json" => Ok(render_json(rows)),
        other => Err(format!(
            "unknown --format {other:?} (expected table, tsv, or json)"
        )),
    }
}

fn render_table(rows: &[OutputRow]) -> String {
    let mut out = String::new();
    writeln!(out, "policy: {}", rows[0].assessment.policy_revision).ok();
    writeln!(out, "cell\tclass\treasons\tsource_pps\tpacket_pps\tsrt_total_bps\tbdp_packets\trecovery_margin_ms\thost_utilization\tnic_utilization").ok();
    for row in rows {
        let d = &row.assessment.derived;
        writeln!(
            out,
            "{}\t{}\t{}\t{:.3}\t{}\t{}\t{}\t{}\t{}\t{}",
            tsv(&row.cell),
            row.assessment.class.name(),
            reasons(&row.assessment),
            d.source_pps_total,
            availability_text(d.host_packet_work_pps),
            availability_text(d.srt_total_bps),
            availability_text(d.bdp_packets),
            availability_text(d.one_repair_margin_ms),
            availability_text(d.host_pps_utilization),
            availability_text(d.nic_utilization),
        )
        .ok();
    }
    out
}

fn render_tsv(rows: &[OutputRow]) -> String {
    let mut out = String::new();
    writeln!(out, "{}", OUTPUT_COLUMNS.join("\t")).ok();
    for row in rows {
        writeln!(out, "{}", row_tsv(row)).ok();
    }
    out
}

fn row_tsv(row: &OutputRow) -> String {
    let d = &row.assessment.derived;
    [
        tsv(&row.cell),
        row.assessment.class.name().to_string(),
        reasons(&row.assessment),
        format!("{:.6}", d.source_pps_total),
        availability_text(d.host_packet_work_pps),
        availability_text(d.srt_total_bps),
        availability_text(d.udp_ip_bps),
        availability_text(d.nic_wire_bps),
        availability_text(d.retransmission_factor),
        availability_text(d.bdp_packets),
        availability_text(d.required_window_packets),
        availability_text(d.flow_window_headroom_packets),
        availability_text(d.receive_window_headroom_packets),
        availability_text(d.one_repair_margin_ms),
        availability_text(d.effective_receive_socket_buffer_horizon_seconds),
        availability_text(d.effective_send_socket_buffer_horizon_seconds),
        availability_text(d.host_pps_utilization),
        availability_text(d.nic_utilization),
        d.admission_waves.to_string(),
        tsv(&row.assessment.policy_revision),
    ]
    .join("\t")
}

fn render_json(rows: &[OutputRow]) -> String {
    let mut out = String::from("[\n");
    for (index, row) in rows.iter().enumerate() {
        if index > 0 {
            out.push_str(",\n");
        }
        out.push_str(&row_json(row));
    }
    out.push_str("\n]\n");
    out
}

fn row_json(row: &OutputRow) -> String {
    let d = &row.assessment.derived;
    format!(
        "  {{\"cell\":\"{}\",\"class\":\"{}\",\"reasons\":[{}],\"source_pps_total\":{},\"packet_pps\":{},\"srt_total_bps\":{},\"udp_ip_bps\":{},\"nic_wire_bps\":{},\"retransmission_factor\":{},\"bdp_packets\":{},\"required_window_packets\":{},\"flow_window_headroom_packets\":{},\"receive_window_headroom_packets\":{},\"recovery_margin_ms\":{},\"socket_horizon_recv_s\":{},\"socket_horizon_send_s\":{},\"host_utilization\":{},\"nic_utilization\":{},\"admission_waves\":{},\"policy_rev\":\"{}\"}}",
        json_string(&row.cell),
        row.assessment.class.name(),
        row.assessment
            .reasons
            .iter()
            .map(|reason| format!("\"{}\"", reason.code()))
            .collect::<Vec<_>>()
            .join(","),
        d.source_pps_total,
        json_availability(d.host_packet_work_pps),
        json_availability(d.srt_total_bps),
        json_availability(d.udp_ip_bps),
        json_availability(d.nic_wire_bps),
        json_availability(d.retransmission_factor),
        json_availability(d.bdp_packets),
        json_availability(d.required_window_packets),
        json_availability(d.flow_window_headroom_packets),
        json_availability(d.receive_window_headroom_packets),
        json_availability(d.one_repair_margin_ms),
        json_availability(d.effective_receive_socket_buffer_horizon_seconds),
        json_availability(d.effective_send_socket_buffer_horizon_seconds),
        json_availability(d.host_pps_utilization),
        json_availability(d.nic_utilization),
        d.admission_waves,
        json_string(&row.assessment.policy_revision),
    )
}

fn reasons(assessment: &CapacityAssessment) -> String {
    assessment
        .reasons
        .iter()
        .map(|reason| reason.code())
        .collect::<Vec<_>>()
        .join(",")
}

fn availability_text<T: std::fmt::Display>(value: Availability<T>) -> String {
    match value {
        Availability::Known(value) => value.to_string(),
        Availability::Unknown => "unknown".to_string(),
        Availability::NotApplicable => "n/a".to_string(),
    }
}

fn json_availability(value: Availability<f64>) -> String {
    match value {
        Availability::Known(value) => format!("{{\"state\":\"known\",\"value\":{value}}}"),
        Availability::Unknown => "{\"state\":\"unknown\"}".to_string(),
        Availability::NotApplicable => "{\"state\":\"not-applicable\"}".to_string(),
    }
}

fn json_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn tsv(value: &str) -> String {
    value.replace(['\t', '\n', '\r'], " ")
}

fn policy_from_cli(cli: &crate::Cli) -> Result<ClassifierPolicy, String> {
    let mut policy = ClassifierPolicy::default();
    policy.revision = cli
        .flags
        .get("policy-rev")
        .cloned()
        .unwrap_or_else(|| policy.revision.clone());
    policy.minimum_window_headroom_packets = flag_f64(cli, "min-window-headroom", 0.0)?;
    policy.minimum_recovery_margin_ms = flag_f64(cli, "min-recovery-margin-ms", 0.0)?;
    policy.minimum_socket_horizon_seconds = flag_f64(cli, "min-socket-horizon-s", 0.0)?;
    policy.max_host_pps_utilization = flag_f64(cli, "max-host-utilization", 1.0)?;
    policy.max_nic_utilization = flag_f64(cli, "max-nic-utilization", 1.0)?;
    policy.max_control_pps = optional_f64(cli, "max-control-pps")?;
    policy.max_admission_waves = optional_u64(cli, "max-admission-waves")?;
    Ok(policy)
}

fn input_from_cli(
    cli: &crate::Cli,
    cell: &BTreeMap<String, String>,
) -> Result<CapacityInput, String> {
    let (workload, bond) = workload_from_cli(cli, cell)?;
    let protocol = protocol_from_cli(cli, cell, bond)?;
    let network = network_from_cli(cli, cell)?;
    let host = host_from_cli(cli, cell, workload.physical_connections)?;
    let connect_cc = value_u64(cli, cell, &["connect-concurrency", "connect-cc"], 1)?;
    Ok(CapacityInput {
        workload,
        protocol,
        network,
        host,
        admission: AdmissionEnvelope { connect_cc },
    })
}

fn workload_from_cli(
    cli: &crate::Cli,
    cell: &BTreeMap<String, String>,
) -> Result<(WorkloadEnvelope, BondMode), String> {
    let source_bps = value_u64(
        cli,
        cell,
        &["source-bps", "source-bitrate-bps", "bitrate"],
        8_000_000,
    )?;
    let physical_connections = value_u64(cli, cell, &["connections"], 1)?;
    let bond_value = value(cli, cell, &["bond"]).unwrap_or("none");
    let (bond, bond_pairs) = parse_bond(bond_value)?;
    let logical_default =
        physical_connections.saturating_sub(bond_pairs.min(physical_connections / 2));
    let logical_streams = value_u64(cli, cell, &["logical-streams"], logical_default)?;
    let source_streams = value_u64(cli, cell, &["source-streams"], logical_streams)?;
    let payload_bytes = value_u64(cli, cell, &["payload-bytes"], crate::PAYLOAD_SIZE as u64)?;
    let duration_secs = value_f64(cli, cell, &["duration-secs", "secs"], 1.0)?;
    if !duration_secs.is_finite() || duration_secs <= 0.0 {
        return Err("duration-secs must be finite and positive".to_string());
    }
    Ok((
        WorkloadEnvelope {
            source_bps_per_stream: source_bps,
            source_streams,
            physical_connections,
            logical_streams,
            payload_bytes,
            duration: Duration::from_secs_f64(duration_secs),
        },
        bond,
    ))
}

fn protocol_from_cli(
    cli: &crate::Cli,
    cell: &BTreeMap<String, String>,
    bond: BondMode,
) -> Result<ProtocolEnvelope, String> {
    let bandwidth = match value(cli, cell, &["srt-bandwidth"]) {
        None => SrtBandwidthPolicy::default(),
        Some(raw) => crate::source::BandwidthPolicy::parse(raw)
            .map(SrtBandwidthPolicy::from)
            .ok_or_else(|| format!("invalid --srt-bandwidth {raw:?}"))?,
    };
    let encryption = parse_encryption(value(cli, cell, &["encryption"]).unwrap_or("plain"))?;
    Ok(ProtocolEnvelope {
        bandwidth,
        encryption,
        flow_window_packets: value_u64(
            cli,
            cell,
            &["flow-window", "flow-window-packets"],
            shiguredo_srt::DEFAULT_FLOW_WINDOW as u64,
        )? as u32,
        receive_window_packets: value_u64(
            cli,
            cell,
            &["receive-window", "receive-window-packets"],
            shiguredo_srt::DEFAULT_FLOW_WINDOW as u64,
        )? as u32,
        tsbpd_latency_ms: value_u64(cli, cell, &["tsbpd-latency-ms", "latency-ms"], 120)?,
        ack_interval: Duration::from_micros(shiguredo_srt::ACK_INTERVAL_MICROS),
        light_ack_interval_packets: shiguredo_srt::LIGHT_ACK_INTERVAL_PACKETS,
        nak_interval: Duration::from_micros(shiguredo_srt::PERIODIC_NAK_INTERVAL_MICROS),
        keepalive_interval: Duration::from_micros(shiguredo_srt::KEEPALIVE_INTERVAL_MICROS),
        periodic_nak_enabled: true,
        bond,
    })
}

fn network_from_cli(
    cli: &crate::Cli,
    cell: &BTreeMap<String, String>,
) -> Result<NetworkEnvelope, String> {
    let rtt = duration_value(cli, cell, &["rtt-ms"]).or_else(|| {
        duration_value(cli, cell, &["link-delay"]).map(|delay| delay.saturating_mul(2))
    });
    let jitter = duration_value(cli, cell, &["rtt-jitter-ms"]).or_else(|| {
        duration_value(cli, cell, &["link-jitter"]).map(|delay| delay.saturating_mul(2))
    });
    let loss = probability_value(cli, cell, &["loss", "link-loss"], 0.0)?;
    let reorder = probability_value(cli, cell, &["reorder", "link-reorder"], 0.0)?;
    Ok(NetworkEnvelope {
        expected_rtt: rtt.map_or(Availability::Unknown, Availability::Known),
        rtt_jitter: jitter.map_or(Availability::Unknown, Availability::Known),
        expected_loss_probability: Availability::Known(loss),
        expected_reorder_probability: Availability::Known(reorder),
        udp_ip_header_bytes: 28,
        nic_link_overhead_bytes: Availability::Known(0),
    })
}

fn host_from_cli(
    cli: &crate::Cli,
    cell: &BTreeMap<String, String>,
    physical_connections: u64,
) -> Result<HostEnvelope, String> {
    let ingress = value(cli, cell, &["ingress"]).unwrap_or("per-port");
    let socket_fan_in = value_u64(
        cli,
        cell,
        &["socket-fan-in"],
        inferred_fan_in(ingress, physical_connections),
    )?;
    let requested_socket = socket_value(cli, cell, &["sock-buf", "socket-buffer-bytes"], 0)?;
    let effective_receive = availability_u64(
        cli,
        cell,
        &["effective-receive-buffer", "effective-rx-buffer"],
    )?
    .unwrap_or(Availability::Unknown);
    let effective_send =
        availability_u64(cli, cell, &["effective-send-buffer", "effective-tx-buffer"])?
            .unwrap_or(Availability::Unknown);
    let nic =
        if value(cli, cell, &["nic"]).is_some_and(|value| value == "loopback" || value == "n/a") {
            Availability::NotApplicable
        } else {
            availability_u64(cli, cell, &["nic-capacity-bps", "nic-bps-capacity"])?
                .unwrap_or(Availability::Unknown)
        };
    let host_pps = availability_f64(cli, cell, &["host-pps-capacity", "host-pps"])?
        .unwrap_or(Availability::Unknown);
    let workers = value_u64(cli, cell, &["workers"], 1)?;
    let host = HostEnvelope {
        requested_receive_socket_buffer_bytes: requested_socket,
        requested_send_socket_buffer_bytes: requested_socket,
        effective_receive_socket_buffer_bytes: effective_receive,
        effective_send_socket_buffer_bytes: effective_send,
        socket_fan_in,
        host_pps_capacity: host_pps,
        nic_capacity_bps: nic,
        cpu_allocation: value(cli, cell, &["cpus"])
            .unwrap_or("unspecified")
            .to_string(),
        workers,
    };
    Ok(host)
}

fn input_from_bench_config(cfg: &crate::BenchConfig) -> CapacityInput {
    let bond = match cfg.bond_mode {
        crate::BondMode::None => BondMode::None,
        crate::BondMode::Broadcast => BondMode::Broadcast,
        crate::BondMode::Backup => BondMode::Backup,
    };
    let logical_streams = cfg.logical_connection_count() as u64;
    let rtt = duration_value_raw(&cfg.link.delay).map(|delay| delay.saturating_mul(2));
    let jitter = duration_value_raw(&cfg.link.jitter).map(|delay| delay.saturating_mul(2));
    let loss = probability_raw(&cfg.link.loss).unwrap_or(0.0);
    let reorder = probability_raw(&cfg.link.reorder).unwrap_or(0.0);
    let nic = if cfg.host == "127.0.0.1" || cfg.host == "localhost" {
        Availability::NotApplicable
    } else {
        Availability::Unknown
    };
    CapacityInput {
        workload: WorkloadEnvelope {
            source_bps_per_stream: cfg.source_bitrate_bps,
            source_streams: logical_streams,
            physical_connections: cfg.connections as u64,
            logical_streams,
            payload_bytes: crate::PAYLOAD_SIZE as u64,
            duration: Duration::from_secs_f64(cfg.stream_secs),
        },
        protocol: ProtocolEnvelope {
            bandwidth: cfg.bandwidth.into(),
            encryption: cfg.encryption.into(),
            tsbpd_latency_ms: cfg.latency_ms as u64,
            bond,
            ..ProtocolEnvelope::default()
        },
        network: NetworkEnvelope {
            expected_rtt: rtt.map_or(Availability::Unknown, Availability::Known),
            rtt_jitter: jitter.map_or(Availability::Unknown, Availability::Known),
            expected_loss_probability: Availability::Known(loss),
            expected_reorder_probability: Availability::Known(reorder),
            udp_ip_header_bytes: 28,
            nic_link_overhead_bytes: Availability::Known(0),
        },
        host: HostEnvelope {
            requested_receive_socket_buffer_bytes: cfg.sock_buf_bytes as u64,
            requested_send_socket_buffer_bytes: cfg.sock_buf_bytes as u64,
            effective_receive_socket_buffer_bytes: Availability::Unknown,
            effective_send_socket_buffer_bytes: Availability::Unknown,
            socket_fan_in: cfg.peers_per_socket() as u64,
            host_pps_capacity: Availability::Unknown,
            nic_capacity_bps: nic,
            cpu_allocation: cfg.cpus.to_string(),
            workers: cfg.workers as u64,
        },
        admission: AdmissionEnvelope {
            connect_cc: cfg.connect_concurrency as u64,
        },
    }
}

fn parse_encryption(value: &str) -> Result<EncryptionMode, String> {
    match value {
        "plain" => Ok(EncryptionMode::Plain),
        "128" => Ok(EncryptionMode::Aes128),
        "192" => Ok(EncryptionMode::Aes192),
        "256" => Ok(EncryptionMode::Aes256),
        _ => Err(format!("invalid encryption {value:?}")),
    }
}

fn parse_bond(value: &str) -> Result<(BondMode, u64), String> {
    let (mode, count) = value.split_once([':', '=']).unwrap_or((value, "0"));
    let bond = match mode {
        "none" => return Ok((BondMode::None, 0)),
        "broadcast" => BondMode::Broadcast,
        "backup" => BondMode::Backup,
        _ => return Err(format!("invalid bond {value:?}")),
    };
    let count = count
        .parse::<u64>()
        .map_err(|_| format!("invalid bond pair count {count:?}"))?;
    Ok((bond, count))
}

fn value<'a>(
    cli: &'a crate::Cli,
    cell: &'a BTreeMap<String, String>,
    names: &[&str],
) -> Option<&'a str> {
    names.iter().find_map(|name| {
        cell.get(*name)
            .or_else(|| cell.get(&format!("send-{name}")))
            .or_else(|| cell.get(&format!("recv-{name}")))
            .map(String::as_str)
            .or_else(|| cli.flags.get(*name).map(String::as_str))
    })
}

fn value_u64(
    cli: &crate::Cli,
    cell: &BTreeMap<String, String>,
    names: &[&str],
    default: u64,
) -> Result<u64, String> {
    value(cli, cell, names).map_or(Ok(default), |raw| {
        raw.parse().map_err(|_| format!("invalid integer {raw:?}"))
    })
}

fn value_f64(
    cli: &crate::Cli,
    cell: &BTreeMap<String, String>,
    names: &[&str],
    default: f64,
) -> Result<f64, String> {
    value(cli, cell, names).map_or(Ok(default), |raw| {
        raw.parse().map_err(|_| format!("invalid number {raw:?}"))
    })
}

fn flag_f64(cli: &crate::Cli, name: &str, default: f64) -> Result<f64, String> {
    cli.flags.get(name).map_or(Ok(default), |raw| {
        raw.parse().map_err(|_| format!("invalid --{name} {raw:?}"))
    })
}

fn optional_f64(cli: &crate::Cli, name: &str) -> Result<Option<f64>, String> {
    cli.flags
        .get(name)
        .map(|raw| {
            raw.parse()
                .map(Some)
                .map_err(|_| format!("invalid --{name} {raw:?}"))
        })
        .unwrap_or(Ok(None))
}

fn optional_u64(cli: &crate::Cli, name: &str) -> Result<Option<u64>, String> {
    cli.flags
        .get(name)
        .map(|raw| {
            raw.parse()
                .map(Some)
                .map_err(|_| format!("invalid --{name} {raw:?}"))
        })
        .unwrap_or(Ok(None))
}

fn duration_value(
    cli: &crate::Cli,
    cell: &BTreeMap<String, String>,
    names: &[&str],
) -> Option<Duration> {
    value(cli, cell, names).and_then(duration_value_raw)
}

fn duration_value_raw(raw: &str) -> Option<Duration> {
    let raw = raw.strip_suffix("ms").unwrap_or(raw);
    raw.parse::<f64>()
        .ok()
        .filter(|value| *value >= 0.0)
        .map(|value| Duration::from_secs_f64(value / 1_000.0))
}

fn probability_value(
    cli: &crate::Cli,
    cell: &BTreeMap<String, String>,
    names: &[&str],
    default: f64,
) -> Result<f64, String> {
    value(cli, cell, names).map_or(Ok(default), |raw| {
        probability_raw(raw).ok_or_else(|| format!("invalid probability {raw:?}"))
    })
}

fn probability_raw(raw: &str) -> Option<f64> {
    let percent = raw.strip_suffix('%');
    let value = percent.unwrap_or(raw).parse::<f64>().ok()?;
    let value = if percent.is_some() || value > 1.0 {
        value / 100.0
    } else {
        value
    };
    (0.0..1.0).contains(&value).then_some(value)
}

fn socket_value(
    cli: &crate::Cli,
    cell: &BTreeMap<String, String>,
    names: &[&str],
    default: u64,
) -> Result<u64, String> {
    let Some(raw) = value(cli, cell, names) else {
        return Ok(default);
    };
    if raw == "default" || raw == "0" {
        return Ok(0);
    }
    let (digits, multiplier) = match raw.strip_suffix(['k', 'K']) {
        Some(digits) => (digits, 1 << 10),
        None => match raw.strip_suffix(['m', 'M']) {
            Some(digits) => (digits, 1 << 20),
            None => (raw, 1),
        },
    };
    digits
        .parse::<u64>()
        .map(|value| value * multiplier)
        .map_err(|_| format!("invalid socket buffer {raw:?}"))
}

fn availability_u64(
    cli: &crate::Cli,
    cell: &BTreeMap<String, String>,
    names: &[&str],
) -> Result<Option<Availability<u64>>, String> {
    let Some(raw) = value(cli, cell, names) else {
        return Ok(None);
    };
    match raw {
        "unknown" => Ok(Some(Availability::Unknown)),
        "n/a" | "na" | "not-applicable" => Ok(Some(Availability::NotApplicable)),
        _ => raw
            .parse()
            .map(|value| Some(Availability::Known(value)))
            .map_err(|_| format!("invalid availability {raw:?}")),
    }
}

fn availability_f64(
    cli: &crate::Cli,
    cell: &BTreeMap<String, String>,
    names: &[&str],
) -> Result<Option<Availability<f64>>, String> {
    let Some(raw) = value(cli, cell, names) else {
        return Ok(None);
    };
    match raw {
        "unknown" => Ok(Some(Availability::Unknown)),
        "n/a" | "na" | "not-applicable" => Ok(Some(Availability::NotApplicable)),
        _ => raw
            .parse()
            .map(|value| Some(Availability::Known(value)))
            .map_err(|_| format!("invalid availability {raw:?}")),
    }
}

fn inferred_fan_in(ingress: &str, connections: u64) -> u64 {
    let sockets = ingress
        .split_once([':', '='])
        .and_then(|(kind, count)| {
            matches!(kind, "shared-pool" | "reuseport-multi")
                .then(|| count.parse::<u64>().ok())
                .flatten()
        })
        .or_else(|| {
            ingress
                .strip_prefix("reuseport-single:")
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(connections.max(1));
    connections.div_ceil(sockets.max(1)).max(1)
}

/// Compare persisted pre-run predictions with the canonical observed pair
/// predicate. This reports disagreement; it does not reinterpret the model.
pub fn validate_results(path: &Path, format: &str) -> Result<String, String> {
    let records = crate::harness::read_results(path).map_err(|error| error.to_string())?;
    let mut pairs: BTreeMap<String, (Option<Record>, Option<Record>)> = BTreeMap::new();
    for record in records {
        let Some(role) = record.get("role") else {
            continue;
        };
        let key = result_key(&record);
        let pair = pairs.entry(key).or_default();
        if role == "caller" {
            pair.0 = Some(record);
        } else if role == "listener" {
            pair.1 = Some(record);
        }
    }
    let rows: Vec<ValidationRow> = pairs
        .into_iter()
        .map(|(cell, (caller, listener))| validate_pair(cell, caller, listener))
        .collect();
    match format {
        "json" => Ok(validation_json(&rows)),
        "tsv" => Ok(validation_tsv(&rows)),
        _ => Ok(validation_table(&rows)),
    }
}

#[derive(Clone, Debug)]
struct ValidationRow {
    cell: String,
    predicted: String,
    predicted_reasons: String,
    observed_clean: String,
    agreement: String,
    explanation: String,
}

fn result_key(record: &Record) -> String {
    CONFIG_COLUMNS
        .iter()
        .filter_map(|column| Some(format!("{column}={}", record.get(column)?)))
        .chain([
            format!("rep={}", record.get("rep").unwrap_or("")),
            format!("attempt={}", record.get("attempt").unwrap_or("")),
        ])
        .collect::<Vec<_>>()
        .join(" ")
}

fn validate_pair(cell: String, caller: Option<Record>, listener: Option<Record>) -> ValidationRow {
    let predicted_record = caller.as_ref().or(listener.as_ref());
    let predicted = predicted_record
        .and_then(|record| record.get("model_class_pre"))
        .unwrap_or("missing")
        .to_string();
    let predicted_reasons = predicted_record
        .and_then(|record| record.get("model_reasons_pre"))
        .unwrap_or("")
        .to_string();
    let Some((caller, listener)) = caller.as_ref().zip(listener.as_ref()) else {
        return ValidationRow {
            cell,
            predicted,
            predicted_reasons,
            observed_clean: "incomplete".to_string(),
            agreement: "incomplete".to_string(),
            explanation: "missing caller or listener row".to_string(),
        };
    };
    let Some(metrics) = crate::compare::PairMetrics::compute(caller, listener) else {
        return ValidationRow {
            cell,
            predicted,
            predicted_reasons,
            observed_clean: "unknown".to_string(),
            agreement: "unknown".to_string(),
            explanation: "could not compute canonical pair metrics".to_string(),
        };
    };
    let observed_clean = metrics.is_clean();
    let mismatch = (predicted == CellClass::ProductionCandidate.name() && !observed_clean)
        || (predicted == CellClass::ExceedsEnvelope.name() && observed_clean);
    let explanation = if observed_clean {
        "canonical pair is clean".to_string()
    } else {
        metrics.unclean_reasons().join("; ")
    };
    ValidationRow {
        cell,
        predicted,
        predicted_reasons,
        observed_clean: observed_clean.to_string(),
        agreement: if mismatch { "mismatch" } else { "agreement" }.to_string(),
        explanation,
    }
}

fn validation_tsv(rows: &[ValidationRow]) -> String {
    let mut out = String::from(
        "cell\tpredicted_class\tpredicted_reasons\tobserved_clean\tagreement\texplanation\n",
    );
    for row in rows {
        writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}",
            tsv(&row.cell),
            row.predicted,
            row.predicted_reasons,
            row.observed_clean,
            row.agreement,
            tsv(&row.explanation),
        )
        .ok();
    }
    out
}

fn validation_table(rows: &[ValidationRow]) -> String {
    let mut out = String::from("cell\tpredicted\tobserved_clean\tagreement\texplanation\n");
    for row in rows {
        writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}",
            tsv(&row.cell),
            row.predicted,
            row.observed_clean,
            row.agreement,
            tsv(&row.explanation),
        )
        .ok();
    }
    out
}

fn validation_json(rows: &[ValidationRow]) -> String {
    let values = rows
        .iter()
        .map(|row| {
            format!(
                "{{\"cell\":\"{}\",\"predicted_class\":\"{}\",\"predicted_reasons\":\"{}\",\"observed_clean\":\"{}\",\"agreement\":\"{}\",\"explanation\":\"{}\"}}",
                json_string(&row.cell),
                json_string(&row.predicted),
                json_string(&row.predicted_reasons),
                json_string(&row.observed_clean),
                json_string(&row.agreement),
                json_string(&row.explanation),
            )
        })
        .collect::<Vec<_>>();
    format!("[{}]\n", values.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_json_is_stable_and_typed() {
        let cli = crate::Cli::parse(&[
            "classify".to_string(),
            "--format=json".to_string(),
            "--source-bps=8000000".to_string(),
            "--nic=loopback".to_string(),
        ]);
        let output = classify(&cli).expect("classification");
        assert!(output.contains("\"class\":"));
        assert!(output.contains("\"state\":\"unknown\""));
        assert!(output.contains("\"policy_rev\":\"stage-a-v1-no-unvalidated-margin\""));
    }

    #[test]
    fn plan_expansion_reports_every_cell() {
        let path = std::env::temp_dir().join(format!("srt-classifier-{}", std::process::id()));
        std::fs::write(&path, "bitrate=8000000,16000000\nconnections=1,2\n").expect("write plan");
        let cli = crate::Cli::parse(&[
            "classify".to_string(),
            format!("--plan={}", path.display()),
            "--format=tsv".to_string(),
            "--nic=loopback".to_string(),
        ]);
        let output = classify(&cli).expect("classification");
        std::fs::remove_file(path).expect("remove plan");
        assert_eq!(output.lines().count(), 5);
    }
}
