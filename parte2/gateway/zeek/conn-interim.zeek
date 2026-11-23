# Registos parciais de ligações longas (cuidado n.º 1 da Secção "Solução proposta").
#
# O Zeek só escreve uma ligação no conn.log quando ela termina ou expira. Para não atrasar a
# deteção de ligações longas (ex.: C&C), este script escreve, de ConnInterim::every em
# ConnInterim::every, o estado atual de cada ligação ainda aberta em conn_interim.log, com os
# mesmos campos do conn.log (Conn::Info). Os valores são cumulativos desde o início da ligação.
# O registo final continua a aparecer no conn.log normal.

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

function poll(c: connection, cnt: count): interval
	{
	# Atualiza c$conn (duração, bytes, pacotes, estado) sem fechar a ligação.
	Conn::set_conn(c, F);
	Log::write(ConnInterim::LOG, c$conn);
	return every;
	}

event new_connection(c: connection)
	{
	ConnPolling::watch(c, poll, 0, every);
	}
