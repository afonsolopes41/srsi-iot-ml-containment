# Configuração do Zeek no gateway.
#
# IMPORTANTE: não alterar os timeouts de ligação (tcp_inactivity_timeout, udp_inactivity_timeout, ...).
# Os modelos são treinados com os conn.log do IoT-23, gerados com os valores por omissão;
# mudá-los altera a duração e os contadores dos registos e cria uma diferença treino/protótipo.

@load base/protocols/conn
@load ./conn-interim

# Logs em JSON (uma linha por registo), sem rotação: o detetor lê o ficheiro à medida que cresce.
redef LogAscii::use_json = T;
redef Log::default_rotation_interval = 0secs;

# O tráfego reproduzido com tcprewrite pode ter checksums reescritos (equivalente a "zeek -C").
redef ignore_checksums = T;

# Escrita imediata: por omissão o Zeek junta os registos em lotes antes de os escrever, o que
# atrasaria a deteção (o T_c passaria a depender do tamanho do lote e não do ataque).
event zeek_init() &priority=-10
	{
	Log::set_buf(Conn::LOG, F);
	Log::set_buf(ConnInterim::LOG, F);
	}
