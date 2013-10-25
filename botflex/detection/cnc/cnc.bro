##! This script looks for possible CnC communication between our hosts
##! and a botnet CnC server. For the time being, we look at (i) blacklist matches
##! (ii) high dns failure rate which hints at botnets that use domain flux (domain
##! generation algorithm <http://en.wikipedia.org/wiki/Domain_Generation_Algorithm> ) 


@load botflex/utils/types
@load botflex/config
@load botflex/services/blacklist_mgr

module CNC;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                time             &log;
		src_ip:            addr             &log;
		dns_failures:	   count	    &log;
		ip_cnc:	           string           &log;
		ip_rbn:	           string           &log;
		url_cnc:	   string           &log; 
		url_cnc_dns:       string           &log; 
		msg:		   string           &log;
	};
	
	redef record connection += {
	conn: Info &optional;};

	## Expire interval for the global table concerned with maintaining cnc info
	global wnd_cnc = 5mins;

	## Thresholds for different contributors to the major event cnc
	global dns_failure_threshold = 30;

	global weight_dns_failure = 0.8;
	global weight_cnc_blacklist_match = 1.0;
	global weight_cnc_blacklist_dns_match = 0.5;
	global weight_cnc_signature_match = 0.8;	
	global weight_rbn_blacklist_match = 0.5;

	## Event that can be handled to access the cnc
	## record as it is sent on to the logging framework.
	global log_cnc: event(rec: Info);

	## The event that sufficient evidence has been gathered to declare the
	## CnC phase of botnet infection lifecycle
	global cnc: event( src_ip: addr, weight: double, detailed_name: string );

	global url_blacklist_match: event( our_ip: addr, other_ip: addr, bad_url: string, bl_source: string, tag: string );
	global ip_blacklist_match: event( our_ip: addr, other_ip: addr, bl_source: string, reason: string );

	## The event that a host was seen to make outbound
	## 447/tcp or 447/udp connections which point to
	## Bobax/Kraken/Oderoor infection
	global bobax_match: event( our_ip: addr, other_ip: addr, bad_port: port );

	## The event that a host was seen to making HTTP request
	## that had a URI that matched Conficker signature i.e.
	## the URI ends with search?q=n
	global conficker_match: event( our_ip: addr, other_ip: addr, bad_url: string );
}


## The event that 'dns_failure_threshold' number of failed dns queries
## were observed. This may hint at the use of domain flux as in the case
## of certain botnets such as Torpig and Conficker 
global dns_failure: event( src_ip: addr, query: string );

event bro_init()
	{
	Log::create_stream(CNC::LOG, [$columns=Info, $ev=log_cnc]);
	}

event Input::end_of_data(name: string, source: string) 
	{
	if ( name == "config_stream" )
		{
		if ( "th_dns_failure" in Config::table_config )
			dns_failure_threshold = to_count(Config::table_config["th_dns_failure"]$value);
		else
			print "Cannot find CNC::th_dns_failure";

		if ( "wnd_cnc" in Config::table_config )
			wnd_cnc = string_to_interval(Config::table_config["wnd_cnc"]$value);
		else
			print "Cannot find CNC::wnd_cnc";

		if ( "weight_dns_failure" in Config::table_config )
			weight_dns_failure = to_double(Config::table_config["weight_dns_failure"]$value);
		else
			print "Cannot find CNC::weight_dns_failure";

		if ( "weight_cnc_blacklist_match" in Config::table_config )
			weight_cnc_blacklist_match = to_double(Config::table_config["weight_cnc_blacklist_match"]$value);
		else
			print "Cannot find CNC::weight_cnc_blacklist_match";
		
		if ( "weight_cnc_blacklist_dns_match" in Config::table_config )
			weight_cnc_blacklist_dns_match = to_double(Config::table_config["weight_cnc_blacklist_dns_match"]$value);
		else
			print "Cannot find CNC::weight_cnc_blacklist_dns_match";		
	
		if ( "weight_cnc_signature_match" in Config::table_config )
			weight_cnc_signature_match = to_double(Config::table_config["weight_cnc_signature_match"]$value);
		else
			print "Cannot find CNC::weight_cnc_signature_match";			
		
		if ( "weight_rbn_blacklist_match" in Config::table_config )
			weight_rbn_blacklist_match = to_double(Config::table_config["weight_rbn_blacklist_match"]$value);
		else				
			print "Cannot find CNC::weight_rbn_blacklist_match";
		}
	}

global cnc_info: CNC::Info;

## Called when an entry in the global table table_cnc exceeds certain age, as specified
## in the table attribute create_expire.
function dns_record_expired(t: table[addr] of set[string], idx: any): interval
	{
	return wnd_cnc;
	}

## The global state table that maintains various information pertaining to the
## major event cnc, and is analyzed when a decision has to be made whether
## or not to declare the major event cnc.
global tb_dns_queries: table[addr] of set[string] &create_expire=0sec &expire_func=dns_record_expired;

event CNC::dns_failure( src_ip: addr, query: string )
	{
	if (src_ip !in tb_dns_queries)
		{
		local tmp_set: set[string];
		tb_dns_queries[src_ip] = tmp_set;
		}

	add tb_dns_queries[src_ip][query];

	if( |tb_dns_queries[src_ip]| > dns_failure_threshold )
		{
		local msg = "High DNS failure rate, possible use of botnet domain flux;";
		local weight = weight_dns_failure;
		local detailed_name = "CNC_DNS_HIGH_FAILURE";

		event CNC::cnc( src_ip, weight, detailed_name );		

		## Log cnc related entries
		cnc_info$ts = network_time();
		cnc_info$src_ip = src_ip;
		cnc_info$dns_failures = |tb_dns_queries[src_ip]|;
		delete tb_dns_queries[src_ip];
		#cnc_info$ip_cnc = t[src_ip]$ip_cnc;
		#cnc_info$ip_rbn = t[src_ip]$ip_rbn;
		#cnc_info$url_cnc = t[src_ip]$url_cnc;
		#cnc_info$url_cnc_dns = t[src_ip]$url_cnc_dns;
		cnc_info$msg = msg;

		Log::write(CNC::LOG,cnc_info);
		}				
	}


event CNC::conficker_match( our_ip: addr, other_ip: addr, bad_url: string )
	{
	local msg = "Conficker match (search?q=n);";
	local weight = weight_cnc_signature_match;
	local detailed_name = "CNC_SIG_MATCH_CONFICKER";	

	event CNC::cnc( our_ip, weight, detailed_name );		
	
	## Log cnc related entries
	cnc_info$ts = network_time();
	cnc_info$src_ip = our_ip;
	#cnc_info$dns_failures = |t[src_ip]$queries_dns_failures|;
	cnc_info$ip_cnc = fmt("%s",other_ip);
	#cnc_info$ip_rbn = t[src_ip]$ip_rbn;
	cnc_info$url_cnc = bad_url;
	#cnc_info$url_cnc_dns = t[src_ip]$url_cnc_dns;
	cnc_info$msg = msg;

	Log::write(CNC::LOG,cnc_info);		
	}


event CNC::bobax_match( our_ip: addr, other_ip: addr, bad_port: port )
	{
	local msg = "Bobax match (outbound 447/tcp or udp);";
	local weight = weight_cnc_signature_match;
	local detailed_name = "CNC_SIG_MATCH_BOBAX";	

	event CNC::cnc( our_ip, weight, detailed_name );		
	
	## Log cnc related entries
	cnc_info$ts = network_time();
	cnc_info$src_ip = our_ip;
	#cnc_info$dns_failures = |t[src_ip]$queries_dns_failures|;
	cnc_info$ip_cnc = fmt("%s",other_ip);
	#cnc_info$ip_rbn = t[src_ip]$ip_rbn;
	#cnc_info$url_cnc = t[src_ip]$url_cnc;
	#cnc_info$url_cnc_dns = t[src_ip]$url_cnc_dns;
	cnc_info$msg = msg;

	Log::write(CNC::LOG,cnc_info);	
	}

## Handling the default dns_message event to detect dns NXDOMAIN replies
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
	{
	local id = c$id;
	local outbound = Site::is_local_addr(id$orig_h);

	if(c?$dns)
		{
		if ( c$dns?$rcode_name && c$dns?$qtype_name  )
			{
			if ( c$dns$rcode_name=="NXDOMAIN" && (c$dns$qtype_name=="A" || c$dns$qtype_name=="AAAA") && outbound && c$dns?$query )
				event CNC::dns_failure(id$orig_h,c$dns$query);
			}
		}
	}


event CNC::url_blacklist_match( our_ip: addr, other_ip: addr, bad_url: string, bl_source: string, tag: string )
	{
	local msg = "";
	local weight = 0.0;
	local detailed_name = "";

	if ( tag == "dns" )
		{
		cnc_info$url_cnc_dns = fmt("%s(source: %s)",bad_url,bl_source);

		msg = fmt("DNS query for blacklisted URL (source: %s);", bl_source);
		weight = weight_cnc_blacklist_dns_match;
		detailed_name = "CNC_BLACKLIST_MATCH_DNS";
		}
	else if ( tag == "http" )
		{
		cnc_info$url_cnc = fmt("%s(source: %s)",bad_url,bl_source);

		msg = fmt("HTTP contact with blacklisted URL (source: %s);", bl_source);
		weight = weight_cnc_blacklist_match;
		detailed_name = "CNC_BLACKLIST_MATCH";
		}	

	event CNC::cnc( our_ip, weight, detailed_name );		

	## Log cnc related entries
	cnc_info$ts = network_time();
	cnc_info$src_ip = our_ip;
	#cnc_info$dns_failures = |t[src_ip]$queries_dns_failures|;
	cnc_info$ip_cnc = fmt("%s",other_ip);
	#cnc_info$ip_rbn = t[src_ip]$ip_rbn;
	#cnc_info$url_cnc = bad_url;
	#cnc_info$url_cnc_dns = t[src_ip]$url_cnc_dns;
	cnc_info$msg = msg;

	Log::write(CNC::LOG,cnc_info);
	}


event CNC::ip_blacklist_match( our_ip: addr, other_ip: addr, bl_source: string, reason: string )
	{
	local msg = "";
	local weight = 0.0;
	local detailed_name = "";

	if ( reason == "CnC" )
		{
		cnc_info$ip_cnc = fmt("%s",other_ip);

		msg = fmt("CnC IP blacklist matched (source: %s);", bl_source);
		weight = weight_cnc_blacklist_match;
		detailed_name = "CNC_BLACKLIST_MATCH";	
		}

	else if ( reason == "RBN" )
		{
		cnc_info$ip_rbn = fmt("%s",other_ip);

		msg = fmt("RBN IP blacklist matched (source: %s);", bl_source);
		weight = weight_rbn_blacklist_match;
		detailed_name = "CNC_RBN_BLACKLIST_MATCH";
		}

	event CNC::cnc( our_ip, weight, detailed_name );		

	## Log cnc related entries
	cnc_info$ts = network_time();
	cnc_info$src_ip = our_ip;
	#cnc_info$dns_failures = |t[src_ip]$queries_dns_failures|;
	#cnc_info$ip_cnc = fmt("%s",other_ip);
	#cnc_info$ip_rbn = t[src_ip]$ip_rbn;
	#cnc_info$url_cnc = bad_url;
	#cnc_info$url_cnc_dns = t[src_ip]$url_cnc_dns;
	cnc_info$msg = msg;		

	Log::write(CNC::LOG,cnc_info);
	}
