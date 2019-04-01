Default Log-Format of Apache:

```
LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %O" common
LogFormat "%{Referer}i -> %U" referer
LogFormat "%{User-agent}i" agent
```


* `%h` Host
* `%l` Remote logname (from identd, if supplied).  
* `%t` Time the request was received, in the format [18/Sep/2011:19:18:28 -0400]. The last number indicates the timezone offset from GMT
* `%r` First line of request.
* `%>s` Status. For requests that have been internally redirected, this is the status of the original request. Use %>s for the final status.
* `%O` Bytes sent, including headers. May be zero in rare cases such as when a request is aborted before a response is sent. You need to enable mod_logio to use this.


More Infos: http://httpd.apache.org/docs/current/mod/mod_log_config.html