##! This script analyzes spam activity in the (bot_) attack phase of botnet 
##! infection lifecycle. It does this by setting a threshold on the total number
##! of mx queries made, unique mx queries and total number
##! of smtp queries. 

@load botflex/utils/types
@load botflex/config

module Spam;


export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                time             &log;
		src_ip:		   addr		    &log;
		mx_queries:        count            &log;
		smtp_conns:	   count 	    &log;
		msg:               string           &log;
		
	};
	
	redef record connection += {
	conn: Info &optional;
	};

	## Expire interval for the global table concerned with maintaining cnc info
	global wnd_spam = 5mins;

	## The event that spam.bro reports spam
	global spam: event( src_ip: addr, weight: double, detailed_name: string );

	## Event that can be handled to access the spam
	## record as it is sent on to the logging framework.
	global log_spam: event(rec: Info);

	## Thresholds for different contributors to the major event bot_attack
	global mx_threshold = 0;
	global smtp_threshold = 20;

	global weight_spam_failed_mx = 1.0;
	global weight_spam_failed_smtp = 0.8;
       }

global spam_info:Spam::Info;

event bro_init()
	{
	Log::create_stream(Spam::LOG, [$columns=Info, $ev=log_spam]);
	}

event Input::end_of_data(name: string, source: string) 
	{
	if ( name == "config_stream" )
		{
		if ( "th_smtp" in Config::table_config )
			smtp_threshold = to_count(Config::table_config["th_smtp"]$value);
		else
			print "Could not find Spam::th_smtp";

		if ( "th_mx_queries" in Config::table_config )
			mx_threshold = to_count(Config::table_config["th_mx_queries"]$value);
		else
			print "Could not find Spam::th_mx_queries";

		if ( "wnd_spam" in Config::table_config )
			wnd_spam = string_to_interval(Config::table_config["wnd_spam"]$value);
		else
			print "Could not find Spam::wnd_spam";

		if ( "weight_spam_failed_mx" in Config::table_config )
			weight_spam_failed_mx = to_double(Config::table_config["weight_spam_failed_mx"]$value);
		else
			print "Could not find Spam::weight_spam_failed_mx";

		if ( "weight_spam_failed_smtp" in Config::table_config )
			weight_spam_failed_smtp = to_double(Config::table_config["weight_spam_failed_smtp"]$value);
		else
			print "Could not find Spam::weight_spam_failed_smtp";	
				
		}
	}

## Called when an entry in the global table table_spam exceeds certain age, as specified
## in the table attribute create_expire.
function smtp_record_expired(t: table[addr] of set[string], idx: any): interval
	{
	return wnd_spam;
	}

function mx_record_expired(t: table[addr] of count, idx: any): interval
	{
	return wnd_spam;
	}	

global tb_smtp_conn: table[addr] of set[conn_id] &create_expire=0sec &expire_func=smtp_record_expired;
global tb_mx_query: table[addr] of count &default=0 &create_expire=0sec &expire_func=mx_record_expired;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{	
	if(c$dns$qtype_name == "MX")
		{
		local src_ip = c$dns$id$orig_h;
		local outbound = Site::is_local_addr(src_ip);
		
		if ( outbound )
			{ 
			# Update total mx queries
			++tb_mx_query[src_ip];

			if ( tb_mx_query[src_ip] > mx_threshold )
				{
				local my_msg = "Large number of MX queries made;";
				local weight = weight_spam_failed_mx;
				local detailed_name = "ATTACK_SPAM_MX";

				event Spam::spam( src_ip, weight, detailed_name );

				## Log spam-related entries
				spam_info$ts = network_time();
				spam_info$src_ip = src_ip;
				spam_info$mx_queries = tb_mx_query[src_ip];
				#spam_info$smtp_conns = |t[src_ip]$uniq_smtp|;
				spam_info$msg = my_msg;

				Log::write(Spam::LOG,spam_info);
				delete tb_mx_query[src_ip];			
				}	
			}
		}
	}


event smtp_request(c: connection, is_orig: bool, command: string, arg: string) &priority=5
	{
	local src_ip = c$smtp$id$orig_h;

	local outbound = Site::is_local_addr(src_ip);
		
	if ( outbound )
		{ 
		if (src_ip !in tb_smtp_conn)
			{
			local tmp_set: set[conn_id];
			tb_smtp_conn[src_ip] = tmp_set;
			}

		if(c$id !in tb_smtp_conn[src_ip])
			{
			add tb_smtp_conn[src_ip][c$id]; 
			if ( |tb_smtp_conn[src_ip]| > smtp_threshold)
				{
				local msg = "Large number of SMTP connections initiated;";
				local weight = weight_spam_failed_smtp;
				local detailed_name = "ATTACK_SPAM_HIGH_SMTP";

				event Spam::spam( src_ip, weight, detailed_name );

				## Log spam-related entries
				spam_info$ts = network_time();
				spam_info$src_ip = src_ip;
				#spam_info$mx_queries = |t[src_ip]$n_mx_queries|;
				spam_info$smtp_conns = |tb_smtp_conn[src_ip]|;
				spam_info$msg = msg;

				Log::write(Spam::LOG,spam_info);
				delete tb_smtp_conn[src_ip];
				}	
			}
		}

	}
	


