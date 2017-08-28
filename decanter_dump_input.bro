@load /opt/bro/share/bro/base/protocols/http
@load /opt/bro/share/bro/base/protocols/conn

redef record HTTP::Info += {
	## Write in the log ALL header names and their values
	header_values: set[string]	&optional	&log;
	
	## Add the MAC address of origin of the connection
	mac_orig: string	&optional	&log;
};

event bro_init()
	{
		local filter: Log::Filter = [$name="decanter_http", $path="decanter", $include=set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "mac_orig", "method", "uri", "version", "request_body_len", "proxied", "orig_mime_types", "header_values")];
		#filter$interv = 6 hr;
		Log::add_filter(HTTP::LOG, filter);
		Log::remove_filter(HTTP::LOG, "default");
		Log::disable_stream(Conn::LOG);
		Log::disable_stream(Files::LOG);
	}

event http_all_headers (c: connection, is_orig: bool, hlist: mime_header_list)
	{
	if (c?$http && is_orig ==T)
		{
		local header_set : set[string] = set();
		for (header in hlist)
			{
			local concatenate : string;
			concatenate = hlist[header]$name + "||" + hlist[header]$value;
			add header_set[concatenate];  
			}
		c$http$header_values = header_set;
		}
	if (c$orig?$l2_addr)
		{
		c$http$mac_orig = c$orig$l2_addr;
		}
	}	

