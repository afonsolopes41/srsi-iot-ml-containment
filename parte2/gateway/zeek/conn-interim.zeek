# Registos parciais de ligações longas (cuidado n.º 1 da Secção "Solução proposta").
#
# O Zeek só escreve uma ligação no conn.log quando ela termina ou expira. Para não atrasar a
# deteção de ligações longas (ex.: C&C), este script escreve, de ConnInterim::every em
# ConnInterim::every, o estado atual de cada ligação ainda aberta em conn_interim.log, com os
# mesmos campos do conn.log (Conn::Info). Os valores são cumulativos desde o início da ligação.
# O registo final continua a aparecer no conn.log normal.
#
# No Zeek 9 a função interna Conn::set_conn não é exportada, por isso o preenchimento do
# registo é feito aqui sobre uma CÓPIA de c$conn, com a mesma lógica de
# base/protocols/conn/main.zeek (Zeek 9.0.1). Não altera o registo final.

module ConnInterim;

export {
	redef enum Log::ID += { LOG };
	global log_policy: Log::PolicyHook;

	## Intervalo entre registos parciais da mesma ligação.
	option every: interval = 30sec;
}

event zeek_init() &priority=5
	{
	Log::create_stream(ConnInterim::LOG,
		[$columns=Conn::Info, $path="conn_interim", $policy=log_policy]);
	}

# Cópia literal de conn_state() de base/protocols/conn/main.zeek (Zeek 9.0.1).
function conn_state(c: connection, trans: transport_proto): string
	{
	local os = c$orig$state;
	local rs = c$resp$state;

	local o_inactive = os == TCP_INACTIVE || os == TCP_PARTIAL;
	local r_inactive = rs == TCP_INACTIVE || rs == TCP_PARTIAL;

	if ( trans == tcp )
		{
		if ( rs == TCP_RESET )
			{
			if ( os == TCP_SYN_SENT || os == TCP_SYN_ACK_SENT ||
			     (os == TCP_RESET &&
			      c$orig$size == 0 && c$resp$size == 0) )
				return "REJ";
			else if ( o_inactive )
				return "RSTRH";
			else
				return "RSTR";
			}
		else if ( os == TCP_RESET )
			{
			if ( r_inactive )
				{
				if ( /\^?S[^HAFGIQ]*R.*/ == c$history )
					return "RSTOS0";

				return "OTH";
				}

			return "RSTO";
			}
		else if ( rs == TCP_CLOSED && os == TCP_CLOSED )
			return "SF";
		else if ( os == TCP_CLOSED )
			return r_inactive ? "SH" : "S2";
		else if ( rs == TCP_CLOSED )
			return o_inactive ? "SHR" : "S3";
		else if ( os == TCP_SYN_SENT && rs == TCP_INACTIVE )
			return "S0";
		else if ( os == TCP_ESTABLISHED && rs == TCP_ESTABLISHED )
			return "S1";
		else
			return "OTH";
		}

	else if ( trans == udp )
		{
		if ( os == UDP_ACTIVE )
			return rs == UDP_ACTIVE ? "SF" : "S0";
		else
			return rs == UDP_ACTIVE ? "SHR" : "OTH";
		}

	else
		return "OTH";
	}

# Equivalente ao ramo "fim de ligação" de Conn::set_conn, aplicado a uma cópia.
function snapshot(c: connection): Conn::Info
	{
	local info: Conn::Info;
	if ( c?$conn )
		info = copy(c$conn);
	else
		info = Conn::Info($ts=c$start_time, $uid=c$uid, $id=c$id,
		                  $proto=get_port_transport_proto(c$id$resp_p));

	if ( c$duration > 0secs )
		{
		info$duration = c$duration;
		info$orig_bytes = c$orig$size;
		info$resp_bytes = c$resp$size;
		}
	if ( c$orig?$num_pkts )
		{
		info$orig_pkts = c$orig$num_pkts;
		info$orig_ip_bytes = c$orig$num_bytes_ip;
		info$resp_pkts = c$resp$num_pkts;
		info$resp_ip_bytes = c$resp$num_bytes_ip;
		}
	if ( |c$service| > 0 )
		info$service = to_lower(join_string_set(c$service, ","));

	info$conn_state = conn_state(c, get_port_transport_proto(c$id$resp_p));

	if ( c$history != "" )
		info$history = c$history;

	return info;
	}

function poll(c: connection, cnt: count): interval
	{
	Log::write(ConnInterim::LOG, snapshot(c));
	return every;
	}

event new_connection(c: connection)
	{
	ConnPolling::watch(c, poll, 0, every);
	}
