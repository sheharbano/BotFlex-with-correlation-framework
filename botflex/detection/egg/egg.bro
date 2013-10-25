##! This script analyzes the egg-down/upload phase of botnet infection lifecycle.
##! It sets a threshold on the number of malicious binaries seen and
##! the number of exes trasported over http disguised as some other filetype
##! and uses the evaluate() function to decide if the major event egg_download 
##! should be triggered.

@load base/protocols/http
@load protocols/http/detect-MHR
@load botflex/utils/types
@load botflex/config

module Egg;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                	time             &log;
		our_ip:            	addr             &log;
		egg_ip:                 string  	 &log;
		egg_url:                string  	 &log;
		md5:                    string  	 &log;
		msg:  	 	        string  	 &log;
		
	};
	
	redef record connection += {
	conn: Info &optional;};

	## A structure to hold a url along with its md5 hash
	type IpUrlMD5Record: record {
	    ip: addr;
	    url: string &default="";
	    md5: string &default="";	
	};

	global weight_egg_signature_match = 1.0;
	global weight_disguised_exe = 0.8;
	global weight_small_exe = 0.8;

	## The event that sufficient evidence has been gathered to declare the
	## egg download phase of botnet infection lifecycle
	global egg_download: event( src_ip: addr, weight: double, detailed_name: string  );

	## Event that can be handled to access the egg_download
	## record as it is sent on to the logging framework.
	global log_egg_download: event(rec: Info);

	const exts_to_check = /application\/x-dosexec/    # Windows and DOS executables
	                   | /application\/x-executable/ # *NIX executable binary
	                   &redef;
	const whitelist_small_size = /windowsupdate\.com/    
	                   | /avg\.com/ 
			   | /microsoft\.com/
			   | /adobe\.com/
			   | /softonic\.com/
			   | /macromedia\.com/
	                   &redef;

	const whitelist_ext = /bin$/    
	                   | /solidpkg$/  
			   | /manifest$/
			   | /kdl$/
			   | /patchmanifest$/
			   | /bundle$/
			   | /ini$/
	                   &redef;
}


## The event that an exe was trasported over http with some other extension. 
## This is a common approach for delivering malicious binaries to victim machines
global disguised_exe: event( ts: time, src_ip: addr, dst_ip: addr, url: string );

## The event that the md5 hash of an exe matched Team Cymru's malware hash repository
## For more information, please refer to /policy/protocols/http/detect-MHR
global tcymru_match: event( ts: time, src_ip: addr, dst_ip: addr, url: string, md5: string );

## Hooking into the notices HTTP::Incorrect_File_Type and HTTP::Malware_Hash_Registry_Match
## to generate sub-events that contribute to the major event egg download

redef Notice::policy += {
       [$pred(n: Notice::Info) = {  
               if ( n$note == HTTP::Incorrect_File_Type && ( /application\/x-dosexec/ in n$msg || /application\/x-executable/ in n$msg ) )
                       {
			local c = n$conn;
			local url = HTTP::build_url_http(c$http);
			# It's ok if the extension is .bin and it carries an exe as that's how some
			# software delivers its updates.
			#if ( !( whitelist_ext in url ) )
				event Egg::disguised_exe( n$ts, c$id$orig_h, c$id$resp_h, url );
                       }

               else if ( n$note == HTTP::Malware_Hash_Registry_Match )
                       {
			## FIXME: This is a hack to get md5 and url as n$conn$http is uninitialized at this stage
			## As per /policy/protocols/http/detect-MHR, msg_arr[1]=src_ip, msg_arr[2]=md5, msg_arr[3]=url
			local msg_arr = split(n$msg, /[[:blank:]]*/);

			event Egg::tcymru_match( n$ts, n$src, n$dst, msg_arr[3], msg_arr[2] );
                       }
	
       }]
};

event bro_init() &priority=5
	{
	Log::create_stream(Egg::LOG, [$columns=Info, $ev=log_egg_download]);
	}

event Input::end_of_data(name: string, source: string) 
	{
	if ( name == "config_stream" )
		{
		if ( "weight_egg_signature_match" in Config::table_config )
			weight_egg_signature_match = to_double(Config::table_config["weight_egg_signature_match"]$value);
		else
			print "Can't find Egg::weight_egg_signature_match";

		if ( "weight_disguised_exe" in Config::table_config )
			weight_disguised_exe = to_double(Config::table_config["weight_disguised_exe"]$value);
		else
			print "Can't find Egg::weight_disguised_exe";

		if ( "weight_small_exe" in Config::table_config )
			weight_small_exe = to_double(Config::table_config["weight_small_exe"]$value);
		else
			print "Can't find Egg::weight_small_exe";			
		}
	}

global egg_info: Egg::Info;

event tcymru_match( ts: time, src_ip: addr, dst_ip: addr, url: string, md5: string )
	{
	local outbound = Site::is_local_addr(src_ip);
	local our_ip = outbound? src_ip : dst_ip;
	local other_ip = outbound? dst_ip : src_ip;

	local msg = fmt("Host downloaded exe (md5: %s) tagged as malicious by TeamCymru;",md5);
	local weight = weight_egg_signature_match;
	local detailed_name = "EGG_BLACKLIST_MATCH";

	event Egg::egg_download( our_ip, weight, detailed_name );

	# Log the event
	egg_info$ts = network_time();
	egg_info$our_ip = our_ip;
	egg_info$egg_ip = fmt("%s",dst_ip); 
	egg_info$egg_url = url; 
	egg_info$md5 = md5;
	#egg_info$disguised_ip = "";	
	#local str_disguised_url = setstr_to_string(t[src_ip]$disguised_url, ","); 
	#egg_info$disguised_url = str_disguised_url;
	egg_info$msg = msg;
	Log::write(Egg::LOG, egg_info);
	}


event disguised_exe( ts: time, src_ip: addr, dst_ip: addr, url: string )
	{
	local outbound = Site::is_local_addr(src_ip);
	local our_ip = outbound? src_ip : dst_ip;
	local other_ip = outbound? dst_ip : src_ip;

	local msg = fmt("Host downloaded exe file(s) with misleading extensions (%s);", url);
	local weight = weight_disguised_exe;
	local detailed_name = "EGG_DISGUISED_EXE";

	event Egg::egg_download( our_ip, weight, detailed_name );

	# Log the event
	egg_info$ts = network_time();
	egg_info$our_ip = our_ip;
	egg_info$egg_ip = fmt("%s",other_ip); 
	egg_info$egg_url = url; 
	#egg_info$md5 = "",
	#egg_info$disguised_ip = "";	
	#local str_disguised_url = setstr_to_string(t[src_ip]$disguised_url, ","); 
	#egg_info$disguised_url = str_disguised_url;
	egg_info$msg = msg;
	Log::write(Egg::LOG, egg_info);
	}

event http_message_done (c: connection, is_orig: bool, stat: http_message_stat)
	{
	# Client body file size is not currently supported in this script.
	if ( is_orig || ! c?$http )
		return;

	if ( c$http?$mime_type && !stat$interrupted ) 
			{
			if ( c$http?$host && whitelist_small_size in c$http$host)
				return;
			if (exts_to_check in c$http$mime_type)
				{
				# If file size less than 1 MB (1048576 bytes)
				if ( stat$body_length < 1048576 );
					{
					local outbound = Site::is_local_addr(c$id$orig_h);
					local our_ip = outbound? c$id$orig_h : c$id$resp_h;
					local other_ip = outbound? c$id$resp_h : c$id$orig_h;
					# Log the event
					egg_info$ts = network_time();
					egg_info$our_ip = our_ip;
					egg_info$egg_ip = fmt("%s",other_ip); 
					egg_info$egg_url = HTTP::build_url_http(c$http); 
					#egg_info$md5 = "",
					#egg_info$disguised_ip = "";	
					#local str_disguised_url = setstr_to_string(t[src_ip]$disguised_url, ","); 
					#egg_info$disguised_url = str_disguised_url;
					egg_info$msg = "Downloaded an exe file smaller than 1MB.";
					Log::write(Egg::LOG, egg_info);

    					event Egg::egg_download( our_ip, weight_small_exe, "EGG_SMALL_EXE" );
					}
				}
			}	
	}
