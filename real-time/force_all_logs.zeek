@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/http
@load base/frameworks/notice

event zeek_done() {
    # Lista de logs que queremos garantir
    local logs = {
        "conn.log",
        "dns.log",
        "ssl.log",
        "http.log",
        "weird.log"
    };

    for (log_name in logs) {
        local cmd = fmt("touch %s", log_name);
        system(cmd);
    }
}
