# $Id: 39_HomebridgeUIAPI.pm 32613 2024-10-03 00:00:00Z RalfP $
###############################################################################
#
#     39_HomebridgeUIAPI.pm 
#
#     An FHEM Perl module for controlling of Homebridge-UI
#
#	  https://github.com/RP-Develop/HomebridgeUIAPI
#
#	  Based on
#     - 39_homebridge.pm (justme1968)
#	  - Homebridge UI API Reference via swagger
#
#     many thanks for this pre work 
#     and thanks to all Fhem developers 
#
#################################################################################


package main;

use strict;
use warnings;

use JSON;
use Data::Dumper;

use HttpUtils;

# Modul Constanten #############################################################

use constant VERSION 			   	=> "v0.0.1";

use constant USER_AGENT 		   	=> "Fhem";

# FHEM Modulfunktionen #########################################################

sub
HomebridgeUIAPI_Initialize {
	my ($hash) = @_;

	$hash->{DefFn}    = "HomebridgeUIAPI_Define";
	$hash->{NotifyFn} = "HomebridgeUIAPI_Notify";
	$hash->{UndefFn}  = "HomebridgeUIAPI_Undefine";
 	$hash->{SetFn}    = "HomebridgeUIAPI_Set";
 	$hash->{GetFn}    = "HomebridgeUIAPI_Get";
	$hash->{AttrFn}   = "HomebridgeUIAPI_Attr";
	$hash->{AttrList} = "disable:1,0 accessibilityCheck refreshSettings:1,0 checkToken:0,1 checkStatus:0,1 ".
                      $readingFnAttributes;
}

# Definitions ##################################################################

my %commands 	= (
     				"login" 			=> {"auth" => 0,"method" => "POST","path" => "/api/auth/login","body" => {"username" => "Guest","password" => "password","otp" => "string"}},
             		"settings" 			=> {"auth" => 0,"method" => "GET" ,"path" => "/api/auth/settings"},
             		"noauth" 			=> {"auth" => 0,"method" => "POST","path" => "/api/auth/noauth"},	
             		"check" 			=> {"auth" => 1,"method" => "GET" ,"path" => "/api/auth/check"},
             		"restart"			=> {"auth" => 1,"method" => "PUT" ,"path" => "/api/server/restart"},
             		"restartID"			=> {"auth" => 1,"method" => "PUT" ,"path" => "/api/server/restart/"},
					"status"			=> {"auth" => 1,"method" => "GET" ,"path" => "/api/status/homebridge"},	
					"statusChilds"		=> {"auth" => 1,"method" => "GET" ,"path" => "/api/status/homebridge/child-bridges"},	
				);		
					
################################################################################

sub HomebridgeUIAPI_Define {
	my ($hash, $def) = @_;
	
	my @param = split("[ \t][ \t]*", $def);
	
	return "Usage: define <name> HomebridgeUIAPI <ip:port> [<users> <password>]"  if((@param != 5) && (@param != 3));
	
   	$hash->{NAME}  = $param[0];
	my $name = $hash->{NAME};
	
	$hash->{VERSION} = VERSION;

	Log3 $name, 5, $name.": <Define> called for $name : ".join(" ",@param);
	
	my $host = $param[2];
	
	# nur einmal zulassen
	my $d = $modules{$hash->{TYPE}}{defptr};
	return "$hash->{TYPE} device already defined as $d->{NAME}." if( defined($d) && $name ne $d->{NAME} );
	$modules{$hash->{TYPE}}{defptr} = $hash;
	
	$hash->{NOTIFYDEV} = "global";
	
	$hash->{HOST} = $host;

	my $username = $param[@param-2];
	my $password = $param[@param-1];
	my $usernameEncrypt = HomebridgeUIAPI_encrypt($username);
	my $passwordEncrypt = HomebridgeUIAPI_encrypt($password);

	Log3 $name, 5, "$name: encrypt $username / $password to $usernameEncrypt / $passwordEncrypt";

	$hash->{DEF} = "$host $usernameEncrypt $passwordEncrypt";
				
	$hash->{helper}{username} = $usernameEncrypt;
	$hash->{helper}{password} = $passwordEncrypt;
	
	if( $init_done ) {
		HomebridgeUIAPI_firstConnect($hash);
	} 
	else {
		readingsSingleUpdate($hash, 'state', 'wait of initializing', 1 );
	}
	
	return undef;
}

sub HomebridgeUIAPI_Notify {
	my ($hash,$dev) = @_;
	
	return if($dev->{NAME} ne "global");
	return if(!grep(m/^INITIALIZED|REREADCFG$/, @{$dev->{CHANGED}}));
	
	HomebridgeUIAPI_firstConnect($hash);
	
	return undef;
}

sub HomebridgeUIAPI_Undefine {
	my ($hash, $arg) = @_;
	
	RemoveInternalTimer($hash);
	
	delete $modules{$hash->{TYPE}}{defptr};
	
	return undef;
}

sub HomebridgeUIAPI_Set {
	my ($hash, $name, $cmd, @args) = @_;
	
	my $usage = "Unknown argument $cmd, choose one of Login:noArg LoginNoAuth:noArg Restart";
	
	if( $cmd eq 'Login' ) {
		HomebridgeUIAPI_Login($hash);
		return undef, 1;
	} 
	elsif( $cmd eq 'LoginNoAuth' ) {
		HomebridgeUIAPI_LoginNoAuth($hash);
		return undef, 1;
	}
	elsif( $cmd eq 'Restart' ) {
		HomebridgeUIAPI_Restart($hash,$args[0]);
		return undef, 1;
	}
	
	return $usage;
}


sub HomebridgeUIAPI_Get {
	my ($hash, $name, $cmd, @args) = @_;
	my ($arg, $param) = @args;
	
	my $list = "Settings:noArg checkToken:noArg showAccount:noArg Status:noArg StatusChilds:noArg";
	
	my $dump;
	
	if($cmd eq 'Settings' ) {
		HomebridgeUIAPI_Settings($hash);
		
        return "last received Settings:\n".HomebridgeUIAPI_Dump(Dumper($hash->{helper}{settings}));
	} 
	elsif($cmd eq 'checkToken' ) {
		HomebridgeUIAPI_Check($hash);
		
        return "last received Token check:\n".HomebridgeUIAPI_Dump(Dumper($hash->{helper}{check}));
	} 	
	elsif($cmd eq 'showAccount' ){
		my $username = $hash->{helper}{username};
		my $password = $hash->{helper}{password};

		return 'no username set' if( !$username );
		return 'no password set' if( !$password );

		$username = HomebridgeUIAPI_decrypt( $username );
		$password = HomebridgeUIAPI_decrypt( $password );

		return "username: $username\npassword: $password";
	}
	elsif($cmd eq 'Status' ) {
		HomebridgeUIAPI_Status($hash);
		
        return "last received status of Homebridge:\n".HomebridgeUIAPI_Dump(Dumper($hash->{helper}{status}));
	} 	
	elsif($cmd eq 'StatusChilds' ) {
		HomebridgeUIAPI_StatusChilds($hash);
		
        return "last received status of Homebridge Childs:\n".HomebridgeUIAPI_Dump(Dumper($hash->{helper}{statusChilds}));
	} 	
	
	return "Unknown argument $cmd, choose one of $list";
}

sub HomebridgeUIAPI_Dump {
	my ($dump) = @_;

	$dump =~ s/^\$VAR\d+\s*=\s*\{//;
	$dump =~ s/^ {8}//gms;
	$dump =~ s/\}\;$//;

	return $dump;
}

sub HomebridgeUIAPI_Attr {
	my ($cmd,$name,$attr_name,$attr_value) = @_;
	# $cmd can be "del" or "set"
	# $name is device name
	# $attr_name and $attr_value are Attribute name and value
	my $hash = $main::defs{$name};
	
	$attr_value = "" if (!defined $attr_value);
	
	Log3 $name, 5, $name.": <Attr> called for $attr_name : value = $attr_value";
	
	(Log3 $name, 3, $hash->{TYPE}.": attr ".$name." $cmd $attr_name $attr_value") if(($cmd ne "?") && ($init_done));
	
	if($cmd eq "set") {
        if($attr_name eq "xxx") {
			# value testen
			#if($attr_value !~ /^yes|no$/) {
			#    my $err = "Invalid argument $attr_value to $attr_name. Must be yes or no.";
			#    Log 3, "PhilipsTV: ".$err;
			#    return $err;
			#}""
		}
		elsif($attr_name eq "accessibilityCheck"){
			unless ($attr_value =~ qr/^[0-9]+$/) {
				Log3 $name, 2, $name.": Invalid Time in attr $attr_name : $attr_value";
				return "Invalid Time $attr_value";
			} 
		 	RemoveInternalTimer($hash, "HomebridgeUIAPI_Settings");
		 	HomebridgeUIAPI_Settings($hash);
		}

	}
	elsif($cmd eq "del"){
		#default wieder herstellen
		if($attr_name eq "xxx"){
		    
		}
		elsif($attr_name eq "accessibilityCheck"){
		 	RemoveInternalTimer($hash, "HomebridgeUIAPI_Settings");  
		}

	}
	return undef;
}

sub HomebridgeUIAPI_Request {
    my ( $hash, $command) = @_;
    my $name = $hash->{NAME};

    Log3 $name, 5, $name.": <Request> called";
    
	my $auth	= 0;
	my $method	= "GET";
	my $path	= "";
	my $body;
	my $timeout = AttrVal($name, "requestTimeout", 3);    		# Timeout in s
	
    # command in commands prüfen
    if(exists($commands{$command})){
        $auth 	= $commands{$command}{auth};
        $method = $commands{$command}{method};
        $path 	= $commands{$command}{path};
        $body 	= encode_json($commands{$command}{body}) if(exists($commands{$command}{body})); 
    }
    else{
        Log3 $name, 1, $name.": Error - '$command' - Command not exist!";
        return undef;
    }
    
    my $url = "http://".$hash->{HOST}.$path;
    
    my $header = {
					"Accept" 			=> "*/*",
			 	 	"User-Agent" 		=> USER_AGENT,
			 	 };

	if(($auth) && defined($hash->{helper}{auth}{token_type}) && defined($hash->{helper}{auth}{access_token})){
		$header->{"Authorization"} = $hash->{helper}{auth}{token_type}." ".$hash->{helper}{auth}{access_token};
	}
	
	if(defined($body)){
		$header->{"Content-Type"} = "application/json; charset=utf-8";
	}
	
	my $param = {
					"url"        	=> $url,
					"method"     	=> $method,                                                                                 
					"timeout"    	=> $timeout,
					"header"     	=> $header, 
					"data"       	=> $body, 
					"hash" 			=> $hash,
    				"command" 		=> $command,
					"callback"		=> \&HomebridgeUIAPI_parseRequestAnswer,
					"loglevel" 		=> AttrVal($name, "verbose", 4)
				};

	$body = "not defined" if(!defined($body));

    Log3 $name, 5, $name.": <Request> URL:".$url." send:\n".
            "## Header ############\n".Dumper($param->{header})."\n".
            "## Method ############\n".$method."\n".
            "## Command ###########\n".$command."\n".
            "## Body ##############\n".$body."\n";

	HttpUtils_NonblockingGet( $param );
	
	return undef;
}

sub HomebridgeUIAPI_parseRequestAnswer {
	my ($param, $err, $data) = @_;
	my $hash = $param->{hash};
	my $name = $hash->{NAME};
	
	my $responseData;
	
	my $error 		= "not defined";
	my $message 	= "not defined";
	my $statusCode 	= "not defined";

    if($err ne ""){
        Log3 $name, 1, $name.": error while HTTP requesting ".$param->{url}." - $err"; 
        readingsSingleUpdate($hash, 'state', 'error', 1 );
        return undef;
    }
    elsif($data ne ""){
		Log3 $name, 5, $name.": <parseRequestAnswer> URL:".$param->{url}." returned data:\n".
            "## HTTP-Statuscode ###\n".$param->{code} ."\n".
            "## Data ##############\n".$data."\n".
            "## Header ############\n".$param->{httpheader}."\n";
  
  		# $param->{code} auswerten?
  		unless (($param->{code} == 200) || ($param->{code} == 201) || ($param->{code} == 401) || ($param->{code} == 403)){
	        Log3 $name, 1, $name.": error while HTTP requesting ".$param->{url}." - code: ".$param->{code}; 
	        readingsSingleUpdate($hash, 'state', 'error', 1 );
	        return undef;
  		}
  		
		# testen ob JSON OK ist
		if($data =~ m/\{.*\}/s){
        	eval{
        		$responseData = decode_json($data);
        		HomebridgeUIAPI_convertBool($responseData);
        	};
        	if($@){
		  		my $error = $@;
		  		$error =~ m/^(.*?)\sat\s(.*?)$/;
		    	Log3 $name, 1, $name.": error while HTTP requesting of command '".$param->{command}."' - Error while JSON decode: $1 ";
		    	Log3 $name, 5, $name.": <parseRequestAnswer> JSON decode at: $2";
		    	readingsSingleUpdate($hash, 'state', 'error', 1 );
		    	return undef;
        	}
        	# testen ob Referenz vorhanden
        	if(ref($responseData) ne 'HASH') {
		    	Log3 $name, 1, $name.": error while HTTP requesting of command '".$param->{command}."' - Error, response isn't a reference!";
		    	readingsSingleUpdate($hash, 'state', 'error', 1 );
		    	return undef;
        	}
		}                                                       

       	if($param->{command} eq "settings") { 
       	
       		# für Get
       		$hash->{helper}{settings} = $responseData;

#    		#Timer setzten, Erreichbarkeit prüfen aller 1000s
#    		if(AttrVal($name, "accessibilityCheck", 0) != 0){
#    			RemoveInternalTimer($hash, "HomebridgeUIAPI_Settings");
#    			InternalTimer(gettimeofday() + AttrVal($name, "accessibilityCheck", 0) , "HomebridgeUIAPI_Settings", $hash);
#    		}

       		#$hash->{homebridgeEnableAccessories} = $responseData->{env}{enableAccessories};
       		#$hash->{homebridgeEnableTerminalAccess} = $responseData->{env}{enableTerminalAccess};
			$hash->{homebridgeVersion} = $responseData->{env}{homebridgeVersion};
    		$hash->{homebridgeInstanceName} = $responseData->{env}{homebridgeInstanceName};
    		$hash->{homebridgeNodeVersion} = $responseData->{env}{nodeVersion};
    		$hash->{homebridgePackageName} = $responseData->{env}{packageName};
    		$hash->{homebridgePackageVersion} = $responseData->{env}{packageVersion};
    		$hash->{homebridgePlatform} = $responseData->{env}{platform};
    		#$hash->{homebridgeRunningInDocker} = $responseData->{env}{runningInDocker};
    		#$hash->{homebridgeRunningInSynologyPackage} = $responseData->{env}{runningInSynologyPackage};
    		#$hash->{homebridgeRunningInPackageMode} = $responseData->{env}{runningInPackageMode};
    		#$hash->{homebridgeRunningInLinux} = $responseData->{env}{runningInLinux};
    		#$hash->{homebridgeRunningInFreeBSD} = $responseData->{env}{runningInFreeBSD};
    		#$hash->{homebridgeRunningOnRaspberryPi} = $responseData->{env}{runningOnRaspberryPi};
    		$hash->{homebridgeCanShutdownRestartHost} = $responseData->{env}{canShutdownRestartHost};
    		#$hash->{homebridgeDockerOfflineUpdate} = $responseData->{env}{dockerOfflineUpdate};
    		$hash->{homebridgeServiceMode} = $responseData->{env}{serviceMode};
    		#$hash->{homebridgeTemperatureUnits} = $responseData->{env}{temperatureUnits};
    		$hash->{homebridgeInstanceId} = $responseData->{env}{instanceId};
    		#$hash->{homebridgeSetupWizardComplete} = $responseData->{env}{setupWizardComplete};
    		#$hash->{homebridgeRecommendChildBridges} = $responseData->{env}{recommendChildBridges};
    		
    		$hash->{homebridgeFormAuth} = $responseData->{formAuth};
    		#$hash->{homebridgeTheme} = $responseData->{theme};
    		#$hash->{homebridgeServerTimestamp} = $responseData->{serverTimestamp};
 
 			readingsSingleUpdate($hash, 'state', 'settings successful loaded', 1 );
 			
 			#HomebridgeUIAPI_Check($hash);
 			#InternalTimer(gettimeofday() + 60 , "HomebridgeUIAPI_Check", $hash);
    		
		}
		elsif($param->{command} eq "login"){
			# Login mit user & password
			
			# {"message":"Forbidden","statusCode":403}
       		if(HomebridgeUIAPI_checkError($hash,$responseData,$param->{url})){
       			readingsSingleUpdate($hash, 'state', 'login not successful - check password', 1 );
       			RemoveInternalTimer($hash, "HomebridgeUIAPI_refreshToken");
				return undef;
       		}

			
       		$hash->{helper}{auth}{token_type} = $responseData->{"token_type"};
			$hash->{helper}{auth}{access_token} = $responseData->{"access_token"};
			$hash->{helper}{auth}{expires_in} = $responseData->{"expires_in"};
			
			readingsSingleUpdate($hash, 'state', 'login successful', 1 );

			HomebridgeUIAPI_Check($hash);

			
			# Token erneuern > expires_in -10s
			RemoveInternalTimer($hash, "HomebridgeUIAPI_refreshToken"); 
			InternalTimer(gettimeofday() + $hash->{helper}{auth}{expires_in} - 10 , "HomebridgeUIAPI_refreshToken", $hash); 
			
			return undef;
		}
       	elsif($param->{command} eq "noauth"){
       		# Login ohne user & password

			# {"message":"Forbidden","statusCode":403} / {"message":"Unauthorized","statusCode":401}
       		if(HomebridgeUIAPI_checkError($hash,$responseData,$param->{url})){
       			readingsSingleUpdate($hash, 'state', 'login not successful - check authentication', 1 );
       			RemoveInternalTimer($hash, "HomebridgeUIAPI_refreshToken");
 				return undef;
       		}
       	       		
			$hash->{helper}{auth}{token_type} = $responseData->{"token_type"};
			$hash->{helper}{auth}{access_token} = $responseData->{"access_token"};
			$hash->{helper}{auth}{expires_in} = $responseData->{"expires_in"};
			
			readingsSingleUpdate($hash, 'state', 'login successful', 1 );

			HomebridgeUIAPI_Check($hash);

			# Token erneuern > expires_in -10s
			RemoveInternalTimer($hash, "HomebridgeUIAPI_refreshToken");
			InternalTimer(gettimeofday() + $hash->{helper}{auth}{expires_in} - 10 , "HomebridgeUIAPI_refreshToken", $hash); 
			
			return undef;	
		}	
		elsif($param->{command} eq "check"){
        	# prüft ob Token valid ist
        	
        	# für Get
        	$hash->{helper}{check} = $responseData;

        	if(HomebridgeUIAPI_checkError($hash,$responseData,$param->{url})){
       			#readingsSingleUpdate($hash, 'state', 'authentication token is invalid', 1 );
       			readingsSingleUpdate($hash, 'token', 'invalid', 1 );

				return undef;
       		}
       		
      		# {"status":"OK"}
       		if(exists($responseData->{status})){
       			if($responseData->{status} eq "OK"){
       				#readingsSingleUpdate($hash, 'state', 'authentication token is valid', 1 );
       				readingsSingleUpdate($hash, 'token', 'valid', 1 );
					return undef;
       			}
       		}
       		#readingsSingleUpdate($hash, 'state', 'authentication token is invalid', 1 );
       		readingsSingleUpdate($hash, 'token', 'invalid', 1 );
       		return undef;
		}
		elsif($param->{command} eq "restart"){
			# löst restart aus, valider Token ist notwendig
			
       		if(HomebridgeUIAPI_checkError($hash,$responseData,$param->{url})){
       			readingsSingleUpdate($hash, 'state', 'restart not successful', 1 );
				return undef;
       		}
       		
       		# {"ok":true,"command":"SIGTERM","restartingUI":false}
       		if(exists($responseData->{ok})){
       			if($responseData->{ok}){
       				readingsSingleUpdate($hash, 'state', 'restart successful', 1 );
					return undef;
       			}
       		}
       		readingsSingleUpdate($hash, 'state', 'restart not successful', 1 );
       		return undef;
		}
		elsif($param->{command} eq "status"){
			# holt den aktuellen Status der HB, valider Token ist notwendig

        	# für Get
        	$hash->{helper}{status} = $responseData;
			
       		if(HomebridgeUIAPI_checkError($hash,$responseData,$param->{url})){
       			readingsSingleUpdate($hash, 'status', 'error', 1 );
				return undef;
       		}
       		
       		# {"status": "up"}
       		if(exists($responseData->{status})){
       			readingsSingleUpdate($hash, 'status', $responseData->{status}, 1 );
				return undef;
       		}
       		readingsSingleUpdate($hash, 'status', 'error', 1 );
       		return undef;
		}
		elsif($param->{command} eq "statusChilds"){
			# holt den aktuellen Status der HB, valider Token ist notwendig

        	# für Get
        	$hash->{helper}{statusChilds} = $responseData;
			
#       		if(HomebridgeUIAPI_checkError($hash,$responseData,$param->{url})){
#       			readingsSingleUpdate($hash, 'status', 'error', 1 );
#				return undef;
#       		}
#       		
#       		# {"status": "up"}
#       		if(exists($responseData->{status})){
#       			readingsSingleUpdate($hash, 'status', $responseData->{status}, 1 );
#				return undef;
#       		}
#       		readingsSingleUpdate($hash, 'status', 'error', 1 );
       		return undef;
		}
		else{
			Log3 $name, 5, $name.": <parseRequestAnswer> unhandled command $param->{command}";
		}
		return undef;
    }
    Log3 $name, 1, $name.": error while HTTP requesting URL:".$param->{url}." - no data!";
    return undef;
}

sub HomebridgeUIAPI_checkError {
    my ($hash,$responseData,$url) = @_;
    my $name = $hash->{NAME};
		
	my $error 		= "not defined";
	my $message		= "not defined";
	my $statusCode	= "not defined";

	if((exists($responseData->{message})) || (exists($responseData->{statusCode})) || (exists($responseData->{error}))){
		$error 		= $responseData->{error} if(defined($responseData->{error}));
		$message 	= $responseData->{message} if(defined($responseData->{message}));
		$statusCode = $responseData->{statusCode} if(defined($responseData->{statusCode}));
		Log3 $name, 1, $name.": error while HTTP requesting URL:".$url." - Message: ".$message." | Code: ".$statusCode." | Error: ".$error;	
		return 1;
	}
	
	return 0;
}

sub HomebridgeUIAPI_firstConnect {
    my ($hash) = @_;
    my $name = $hash->{NAME};

    Log3 $name, 5, $name.": <Settings> start";

	HomebridgeUIAPI_Settings($hash);
	
	readingsSingleUpdate($hash, 'token', '', 1 );
	readingsSingleUpdate($hash, 'status', '', 1 );
	
	InternalTimer(gettimeofday() + 20 , "HomebridgeUIAPI_refreshToken", $hash);
	InternalTimer(gettimeofday() + 40 , "HomebridgeUIAPI_accessibilityCheck", $hash);

	return undef;
}

sub HomebridgeUIAPI_refreshToken {
    my ($hash) = @_;
    my $name = $hash->{NAME};

    Log3 $name, 5, $name.": <refreshToken> start";

	HomebridgeUIAPI_Check($hash);

	# Auswahl nach Login methode
	if(exists($hash->{homebridgeFormAuth})){
		
		if($hash->{homebridgeFormAuth}){
			HomebridgeUIAPI_Login($hash);
		}	
		else{
			HomebridgeUIAPI_LoginNoAuth($hash);
		}
		return undef;
	}

	# nochmal veruchen in 1min, wenn Daten noch nicht vorhanden sind
	RemoveInternalTimer($hash, "HomebridgeUIAPI_refreshToken");
	InternalTimer(gettimeofday() + 60 , "HomebridgeUIAPI_refreshToken", $hash); 
    return undef;
}

sub HomebridgeUIAPI_accessibilityCheck {
    my ($hash) = @_;
    my $name = $hash->{NAME};

    Log3 $name, 5, $name.": <refreshStatus> start";
    
    HomebridgeUIAPI_Settings($hash) 	if(AttrVal($name, "refreshSettings", 1));
	HomebridgeUIAPI_Check($hash)		if(AttrVal($name, "checkToken", 0));
	HomebridgeUIAPI_Status($hash)		if(AttrVal($name, "checkStatus", 0));
	HomebridgeUIAPI_StatusChilds($hash)	if(AttrVal($name, "checkStatus", 0));
	# weitere Abfragen hier
	
	#Timer setzten, Erreichbarkeit prüfen aller 3600s
	if(AttrVal($name, "accessibilityCheck", 1)){
		RemoveInternalTimer($hash, "HomebridgeUIAPI_accessibilityCheck");
		InternalTimer(gettimeofday() + AttrVal($name, "accessibilityCheck", 3600) , "HomebridgeUIAPI_accessibilityCheck", $hash);
	}
    return undef;
}

sub HomebridgeUIAPI_Settings {
    my ($hash) = @_;
    my $name = $hash->{NAME};

    Log3 $name, 5, $name.": <Settings> start";
    
	#$hash->{homebridgeEnableAccessories} 			= undef;
	#$hash->{homebridgeEnableTerminalAccess} 		= undef;
	$hash->{homebridgeVersion} 						= undef;
	$hash->{homebridgeInstanceName} 				= undef;
	$hash->{homebridgeNodeVersion} 					= undef;
	$hash->{homebridgePackageName} 					= undef;
	$hash->{homebridgePackageVersion} 				= undef;
	$hash->{homebridgePlatform} 					= undef;
	#$hash->{homebridgeRunningInDocker} 			= undef;
	#$hash->{homebridgeRunningInSynologyPackage} 	= undef;
	#$hash->{homebridgeRunningInPackageMode} 		= undef;
	#$hash->{homebridgeRunningInLinux} 				= undef;
	#$hash->{homebridgeRunningInFreeBSD} 			= undef;
	#$hash->{homebridgeRunningOnRaspberryPi} 		= undef;
	$hash->{homebridgeCanShutdownRestartHost} 		= undef;
	#$hash->{homebridgeDockerOfflineUpdate} 		= undef;
	$hash->{homebridgeServiceMode} 					= undef;
	#$hash->{homebridgeTemperatureUnits} 			= undef;
	$hash->{homebridgeInstanceId} 					= undef;
	#$hash->{homebridgeSetupWizardComplete} 		= undef;
	#$hash->{homebridgeRecommendChildBridges} 		= undef;
	
	$hash->{homebridgeFormAuth} 					= undef;
	#$hash->{homebridgeTheme} 						= undef;
	#$hash->{homebridgeServerTimestamp} 			= undef;
  

	HomebridgeUIAPI_Request($hash,"settings");	
    return undef;
}

sub HomebridgeUIAPI_Login {
    my ($hash) = @_;
    my $name = $hash->{NAME};

    Log3 $name, 5, $name.": <Login> start";
    
	my $username = $hash->{helper}{username};
	my $password = $hash->{helper}{password};

	if (!$username || !$password){
        Log3 $name, 1, $name.": no username or password set"; 
        readingsSingleUpdate($hash,"state","Login failed",1);
        return undef;
	}

	$commands{login}{body}{username} = HomebridgeUIAPI_decrypt($username);
	$commands{login}{body}{password} = HomebridgeUIAPI_decrypt($password);
	
	$hash->{helper}{auth}{token_type} 	= undef;
	$hash->{helper}{auth}{access_token} = undef;
	$hash->{helper}{auth}{expires_in} 	= undef;

	HomebridgeUIAPI_Request($hash,"login");	
    return undef;
}

sub HomebridgeUIAPI_LoginNoAuth {
    my ($hash) = @_;
    my $name = $hash->{NAME};

    Log3 $name, 5, $name.": <LoginNoAuth> start";
    
	$hash->{helper}{auth}{token_type} 	= undef;
	$hash->{helper}{auth}{access_token} = undef;
	$hash->{helper}{auth}{expires_in} 	= undef;

	HomebridgeUIAPI_Request($hash,"noauth");	
    return undef;
}

sub HomebridgeUIAPI_Check {
    my ($hash) = @_;
    my $name = $hash->{NAME};

    Log3 $name, 5, $name.": <Check> start";

	HomebridgeUIAPI_Request($hash,"check");	
    return undef;
}

sub HomebridgeUIAPI_Restart {
    my ($hash,$ID) = @_;
    my $name = $hash->{NAME};

    Log3 $name, 5, $name.": <Restart> start";
    
	if(defined($ID)){
		$commands{restartID}{path} = $commands{restartID}{path}.$ID;
		HomebridgeUIAPI_Request($hash,"restartID");	
	}
	else{
		HomebridgeUIAPI_Request($hash,"restart");			
	}
    return undef;
}

sub HomebridgeUIAPI_Status {
    my ($hash,$ID) = @_;
    my $name = $hash->{NAME};

    Log3 $name, 5, $name.": <Status> start";
    
	HomebridgeUIAPI_Request($hash,"status");			

    return undef;
}

sub HomebridgeUIAPI_StatusChilds {
    my ($hash,$ID) = @_;
    my $name = $hash->{NAME};

    Log3 $name, 5, $name.": <StatusChilds> start";
    
	HomebridgeUIAPI_Request($hash,"statusChilds");			

    return undef;
}



# Password Crypt ###############################################################

sub HomebridgeUIAPI_encrypt {
  	my ($decoded) = @_;
  	my $key = getUniqueId();
  	my $encoded;

  	return $decoded if( $decoded =~ /crypt:/ );

  	for my $char (split //, $decoded) {
    	my $encode = chop($key);
    	$encoded .= sprintf("%.2x",ord($char)^ord($encode));
    	$key = $encode.$key;
  	}

  	return 'crypt:'.$encoded;
}

sub HomebridgeUIAPI_decrypt {
  	my ($encoded) = @_;
  	my $key = getUniqueId();
  	my $decoded;

  	return $encoded if( $encoded !~ /crypt:/ );
  
  	$encoded = $1 if( $encoded =~ /crypt:(.*)/ );

  	for my $char (map { pack('C', hex($_)) } ($encoded =~ /(..)/g)) {
    	my $decode = chop($key);
    	$decoded .= chr(ord($char)^ord($decode));
    	$key = $decode.$key;
  	}

  	return $decoded;
}

# Convert Bool #################################################################

sub HomebridgeUIAPI_convertBool {

    local *_convert_bools = sub {
        my $ref_type = ref($_[0]);
        if ($ref_type eq 'HASH') {
            _convert_bools($_) for values(%{ $_[0] });
        }
        elsif ($ref_type eq 'ARRAY') {
            _convert_bools($_) for @{ $_[0] };
        }
        elsif (
               $ref_type eq 'JSON::PP::Boolean'           # JSON::PP
            || $ref_type eq 'Types::Serialiser::Boolean'  # JSON::XS
        ) {
            $_[0] = $_[0] ? 1 : 0;
        }
        else {
            # Nothing.
        }
    };

    &_convert_bools;

}

################################################################################

# Eval-Rückgabewert für erfolgreiches
# Laden des Moduls
1;

# Beginn der Commandref ########################################################

=pod

=encoding utf8

=item device
=item summary Controlling of HomebridgeUI
=item summary_DE Steuerung der HomebridgeUI

=begin html

<a id="HomebridgeUIAPI"></a>
<h3>
	HomebridgeUIAPI
</h3>
<ul>
  	HomebridgeUIAPI controls the Homebridge UI.<br />
  	<br />
  	<a id="HomebridgeUIAPI-define"></a>
  	<b>Define</b>
  	<ul>
    	<code>define &lt;name&gt; HomebridgeUIAPI &lt;host:port&gt; &lt;username&gt; &lt;password&gt;</code><br />
    	<br />
    	Example: <code>define HomebridgeUI HomebridgeUIAPI 192.168.0.2:8581 username password</code><br />
    	<br />
    	After a short time, a connection to the Homebridge UI should be established.
  	</ul><br />
  	<a id="HomebridgeUIAPI-set"></a>
  	<b>Set</b>
	<ul>
		<a id="HomebridgeUIAPI-set-Login"></a>
		<li><b>Login</b><br />
  			Login with username and password stored in the DEF..
		</li>
		<a id="HomebridgeUIAPI-set-LoginNoAuth"></a>
		<li><b>LoginNoAuth</b><br />
			Login without username and password. A token is still generated for the connection.
		</li>
		<a id="HomebridgeUIAPI-set-Restart"></a>
		<li><b>Restart</b><br />
			Restarts the Homebridge.
		</li>
	</ul><br />
   	<a id="HomebridgeUIAPI-get"></a>
   	<b>Get</b>
  	<ul>
		<a id="HomebridgeUIAPI-get-Settings"></a>
		<li><b>Settings</b><br />
			Returns the complete settings.
		</li>
		<a id="HomebridgeUIAPI-get-checkToken"></a>
		<li><b>checkToken</b><br />
			Returns whether the token is still valid or not.
		</li>
		<a id="HomebridgeUIAPI-get-Status"></a>
		<li><b>Status</b><br />
			Returns the status of the Homebridge (up | pending | down).
		</li>
		<a id="HomebridgeUIAPI-get-StatusChilds"></a>
		<li><b>StatusChilds</b><br />
			Returns the status of the Homebridge Childs.
		</li>
		<a id="HomebridgeUIAPI-get-showAccount"></a>
		<li><b>showAccount</b><br />
			Displays username and password from DEF.
		</li>
   	</ul><br />  	
   	<a id="HomebridgeUIAPI-attr"></a>
   	<b>Attributes</b>
  	<ul>
		<a id="HomebridgeUIAPI-attr-accessibilityCheck"></a>
		<li><b>accessibilityCheck</b><br />
			Default '3600s'<br />
			Can be used to check whether the HomebridgeUI is accessible. Interval in seconds. '0' = disable
		</li>
		<a id="HomebridgeUIAPI-attr-refreshSettings"></a>
		<li><b>refreshSettings</b><br />
			Default '1'<br />
			Activates the query of the settings in the interval of 'accessibilityCheck'.
		</li>
		<a id="HomebridgeUIAPI-attr-checkToken"></a>
		<li><b>checkToken</b><br />
			Default '0'<br />
			Activates the query for the status of the token in the interval of 'accessibilityCheck'.
		</li>
		<a id="HomebridgeUIAPI-attr-checkStatus"></a>
		<li><b>checkStatus</b><br />
			Default '0'<br />
			Activates the query for the status of the Homebridge in the interval of 'accessibilityCheck'.
		</li>
  	</ul><br />
  	<b>Readings</b>
  	<ul>
		<li><b>state</b> - Status.</li>
		<li><b>token</b> - Status of the token, valid/invalid.</li>
		<li><b>status</b> - Status of the Homebridge, up | pending | down .</li>
  	</ul><br />
</ul>

=end html

=begin html_DE

<a id="HomebridgeUIAPI"></a>
<h3>
	HomebridgeUIAPI
</h3>
<ul>
  	HomebridgeUIAPI steuert die Homebridge UI.<br />
  	<br />
  	<a id="HomebridgeUIAPI-define"></a>
  	<b>Define</b>
  	<ul>
    	<code>define &lt;name&gt; HomebridgeUIAPI &lt;host:port&gt; &lt;username&gt; &lt;password&gt;</code><br />
    	<br />
    	Beispiel: <code>define HomebridgeUI HomebridgeUIAPI 192.168.0.2:8581 username password</code><br />
    	<br />
    	Nach kurzer Zeit sollte eine Verbindung zur Homebridge UI aufgebaut sein. 
  	</ul><br />
  	<a id="HomebridgeUIAPI-set"></a>
  	<b>Set</b>
	<ul>
		<a id="HomebridgeUIAPI-set-Login"></a>
		<li><b>Login</b><br />
  			Login mit Username und Password, welche im DEF gespeichert wurden.
		</li>
		<a id="HomebridgeUIAPI-set-LoginNoAuth"></a>
		<li><b>LoginNoAuth</b><br />
			Login ohne Username und Password. Für die Verbindung wird trotzdem ein Token erzeugt.
		</li>
		<a id="HomebridgeUIAPI-set-Restart"></a>
		<li><b>Restart</b><br />
			Führt ein Restart der Homebridge aus.
		</li>
	</ul><br />
   	<a id="HomebridgeUIAPI-get"></a>
   	<b>Get</b>
  	<ul>
		<a id="HomebridgeUIAPI-get-Settings"></a>
		<li><b>Settings</b><br />
			Gibt die kopletten Settings zurück.
		</li>
		<a id="HomebridgeUIAPI-get-checkToken"></a>
		<li><b>checkToken</b><br />
			Gibt zurück, ob der Token noch gültig ist oder nicht.
		</li>
		<a id="HomebridgeUIAPI-get-Status"></a>
		<li><b>Status</b><br />
			Gibt den Status der Homebridge (up | pending | down) zurück.
		</li>
		<a id="HomebridgeUIAPI-get-StatusChilds"></a>
		<li><b>StatusChilds</b><br />
			Gibt den Status der Homebridge Childs zurück.
		</li>
		<a id="HomebridgeUIAPI-get-showAccount"></a>
		<li><b>showAccount</b><br />
			Zeigt Username und Password aus DEF an.
		</li>
   	</ul><br />  	
   	<a id="HomebridgeUIAPI-attr"></a>
   	<b>Attributes</b>
  	<ul>
		<a id="HomebridgeUIAPI-attr-accessibilityCheck"></a>
		<li><b>accessibilityCheck</b><br />
			Default '3600s'<br />
			Kann genutzt werden, um zu prüfen, ob die HomebridgeUI erreichbar ist. Intervall in Sekunden. '0' = disable
		</li>
		<a id="HomebridgeUIAPI-attr-refreshSettings"></a>
		<li><b>refreshSettings</b><br />
			Default '1'<br />
			Aktiviert die Abfrage der Settings im Intervall von 'accessibilityCheck'.
		</li>
		<a id="HomebridgeUIAPI-attr-checkToken"></a>
		<li><b>checkToken</b><br />
			Default '0'<br />
			Aktiviert die Abfrage nach dem Status des Token im Intervall von 'accessibilityCheck'.
		</li>
		<a id="HomebridgeUIAPI-attr-checkStatus"></a>
		<li><b>checkStatus</b><br />
			Default '0'<br />
			Aktiviert die Abfrage nach dem Status der Homebridge im Intervall von 'accessibilityCheck'.
		</li>
  	</ul><br />
  	<b>Readings</b>
  	<ul>
		<li><b>state</b> - Status.</li>
		<li><b>token</b> - Status des Token, valid/invalid.</li>
		<li><b>status</b> - Status der Homebridge, up | pending | down .</li>
  	</ul><br />
</ul>

=end html_DE

=cut