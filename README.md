# ngx_metrics

ngx_metrics collects nginx performance metrics via syslog feed from nginx and
makes them available for prometheus to scrape.

## nginx configuration

```
http {

    # ...

    # $body_bytes_sent		number of bytes sent to a client, not counting the response header
    # $bytes_sent		the number of bytes sent to a client
    # $connections_active	The current number of active client connections including Waiting connections.
    # $connections_reading	The current number of connections where nginx is reading the request header.
    # $connections_waiting	The current number of idle client connections waiting for a request.
    # $connections_writing	The current number of connections where nginx is writing the response back to the client.
    # $host			in this order of precedence: host name from the request line, or host name from the “Host” request header field, or the server name matching a request
    # $request_length		request length (including request line, header, and request body)
    # $request_time		request processing time in seconds with a milliseconds resolution; time elapsed between the first bytes were read from the client and the log write after the last bytes were sent to the client
    # $status			response status
    # $ancient_browser		equals the value set by the ancient_browser_value directive, if a browser was identified as ancient;
    # $pipe			“p” if request was pipelined, “.” otherwise
    # $remote_user		user name supplied with the Basic authentication
    # $request_completion	“OK” if a request has completed, or an empty string otherwise 
    # $server_name		name of the server which accepted a request
    # $server_protocol		request protocol, usually “HTTP/1.0”, “HTTP/1.1”, or “HTTP/2.0”

    log_format ngx_metrics escape=json '{'
        '"AncientBrowser":"$ancient_browser",'
        '"BodyBytesSent":$body_bytes_sent,'
        '"BytesSent":$bytes_sent,'
        '"ConnectionsActive":$connections_active,'
        '"ConnectionsReading":$connections_reading,'
        '"ConnectionsWaiting":$connections_waiting,'
        '"ConnectionsWriting":$connections_writing,'
        '"Host":"$host",'
        '"Pipe":"$pipe",'
        '"RemoteUser":"$remote_user",'
        '"RequestCompletion":"$request_completion",'
        '"RequestLength":$request_length,'
        '"RequestTime":$request_time,'
        '"Scheme":"$scheme",'
        '"ServerName":"$server_name",'
        '"ServerProtocol":"$server_protocol",'
        '"Status":"$status"'
    '}';

    # ...

    access_log syslog:server=127.0.0.1:9514 ngx_metrics;

    # ...
}
```
