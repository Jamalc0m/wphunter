#!/usr/bin/php
<?php
error_reporting(0);
function sendRequest($url,$ssl=false){
	$agent ="'Mozilla/5.0 (Windows NT 6.2; WOW64; rv:17.0) Gecko/20100101 Firefox/17.0';";
	$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL,trim($url));
			curl_setopt($ch, CURLOPT_USERAGENT,$agent);
	        curl_setopt($ch, CURLOPT_REFERER, 'https://www.google.com/');
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_HEADER, 0);
			curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $ssl);
			curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,$ssl);
			curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
			curl_setopt($ch, CURLOPT_VERBOSE, 0);
			$result = curl_exec($ch);
			//$dd=curl_getinfo($ch);
			//var_dump($dd);
			if (!$result)
			die(curl_error($ch));
			return $result;
			curl_close($ch);
		 	
}

function path_disclosure($url){
	
	// echo "
	//                         .;lc'
	//                     .,cdkkOOOko;.
	//                  .,lxxkkkkOOOO000Ol'
	//              .':oxxxxxkkkkOOOO0000KK0x:'
	//           .;ldxxxxxxxxkxl,.'lk0000KKKXXXKd;.
	//        ':oxxxxxxxxxxo;.       .:oOKKKXXXNNNNOl.
	//       '';ldxxxxxdc,.              ,oOXXXNNNXd;,.
	//      .ddc;,,:c;.         ,c:         .cxxc:;:ox:
	//      .dxxxxo,     .,   ,kMMM0:.  .,     .lxxxxx:
	//      .dxxxxxc     lW. oMMMMMMMK  d0     .xxxxxx:
	//      .dxxxxxc     .0k.,KWMMMWNo :X:     .xxxxxx:
	//      .dxxxxxc      .xN0xxxxxxxkXK,      .xxxxxx:
	//      .dxxxxxc    lddOMMMMWd0MMMMKddd.   .xxxxxx:
	//      .dxxxxxc      .cNMMMN.oMMMMx'      .xxxxxx:
	//      .dxxxxxc     lKo;dNMN.oMM0;:Ok.    'xxxxxx:
	//      .dxxxxxc    ;Mc   .lx.:o,    Kl    'xxxxxx:
	//      .dxxxxxdl;. .,               .. .;cdxxxxxx:
	//      .dxxxxxxxxxdc,.              'cdkkxxxxxxxx:
	//       .':oxxxxxxxxxdl;.       .;lxkkkkkxxxxdc,.
	//           .;ldxxxxxxxxxdc, .cxkkkkkkkkkxd:.
	//              .':oxxxxxxxxx.ckkkkkkkkxl,.
	//                  .,cdxxxxx.ckkkkkxc.
	//                     .':odx.ckxl,.
	//                         .,.'";//
	/** 
	 * the logo to be changed later 
	*/ 
	 	$agent ="'Mozilla/5.0 (Windows NT 6.2; WOW64; rv:17.0) Gecko/20100101 Firefox/17.0';";
	 	$dir_listening =  array("wp-includes/ms-settings.php","wp-includes/post-template.php",'wp-includes/shortcodes.php','wp-includes/rss-functions.php');
		// echo '------------------------------------------------';
		 for($i=0;$i<=count($dir_listening);$i++){
			$data=sendRequest($url.$dir_listening[$i],0);
			$var='Fatal error'; //require_once
		 	if (strchr($data,$var)) {
				 echo "Path disclosure vulerability found at:".$data."\n\r";
			}
		 }

	}

	function security_header_check($url){
		$host=parse_url($url);
		$result= get_headers($url,1);
		foreach ( $result as $key=>$header )  {
			$result[strtoupper($key)] = $header;
		}
			$search = array('Strict-Transport-Security','Content-Security-Policy','X-Frame-Options','X-XSS-Protection',
			'X-Content-Type-Options','Referrer-Policy');
			echo "\033[1;33m Missing Headers: \033[0m".PHP_EOL;
			list($a,$b,$c,$d,$e,$f) = $search;
				
			if (isset($result[strtoupper($a)])) {
				echo $a.'Protects against man-in-the-middle attacks is set'.PHP_EOL;
				}else
				echo $a."Protects against man-in-the-middle attacks is \033[1;31m not set \033[0m".PHP_EOL;
			if (isset($result[strtoupper($b)])) {
				echo $b.'Prevents possible phishing or XSS attacks is set'.PHP_EOL;
				}else 
				echo $b."Prevents possible phishing or XSS attacks is\033[1;31m  Not set\033[0m".PHP_EOL;
			if (isset($result[strtoupper($c)])) {
				 echo $c.'Protects against Clickjacking attacks is set'.PHP_EOL;
				}else 
				 echo $c."Protects against Clickjacking attacks is \033[1;31m Not set\033[0m".PHP_EOL;
		
			if (isset($result[strtoupper($d)])) {
				echo $d.' Mitigates Cross-Site Scripting (XSS) attacks is set'.PHP_EOL;
				}else 
				echo $d."  Mitigates Cross-Site Scripting (XSS) attacks is\033[1;31m  Not set\033[0m".PHP_EOL;
		
			if (isset($result[strtoupper($e)])) {
				echo $e.'Prevents possible phishing or XSS attacks is set'.PHP_EOL;
				}else 
				echo $e." Prevents possible phishing or XSS attacks is \033[1;31m Not set\033[0m".PHP_EOL;
		
			if (isset($result[strtoupper($f)])) {
				echo $f.'Prevents possible phishing or XSS attacks is set'.PHP_EOL;
				}else 
				echo $f." Protects against Clickjacking attacks is \033[1;31m Not set\033[0m".PHP_EOL;		
	}	
	
	function backup_fuzzer($url){
		$OriginalUserAgent = ini_get('user_agent');
		ini_set('user_agent', 'Mozilla/5.0');
	   $data= array('info.php','wp-config.php~','wp-config.php.save','test.php','wp-config.php.swp','wp-config.php.swp','wp-config.php.swo','wp-config.php_bak','index.php.bak','wp-config.old','wp-config.php1','wp-config.php2','wp-config.php.tmp','wp-config-backup.php','wp-config.bak', 'wp-config.php.bak', 'wp-config.save', 'wp-config.old', 'wp-config.php.old','wp-config.php.orig','wp-config.orig','wp-config.php.original', 'wp-config.original','wp-config.txt','.git','.svn','.htaccess','.git/info');
		$count='';
		for($i=0;$i<count($data);$i++){
			$response=get_headers($url.$data[$i],1);
			//echo "<pre>";
			$res=$http_response_header[0];
			//print_r($res);
			if (strchr($res,'200')) {
				echo "\033[1;35m interesting File found: \033[0m".$url.$data[$i]."\n";
			}
		}
	}

	//Main Function
	function chota(){
		echo "\033[1;33m 
	    (((((              )))))
	   ((((((              ))))))
	   ((((((              ))))))
	    (((((,r@@@@@@@@@@e,)))))
	     (((@@@@@@@@@@@@@@@@)))
	      \@@/,:::,\/,:::,\@@
	     /@@@|:::::||:::::|@@@\
	    / @@@\':::'/\':::'/@@@ \
	   /  /@@@@@@@//\\@@@@@@@\  \
	  (  /  '@@@@@====@@@@@'  \  )
	   \(     /          \     )/
	     \   (            )   /
	          \          /
	     WPHunter.co"."\033[0m".PHP_EOL;
	$param = $_SERVER["argv"][1];

	if($param == '-h'|| $param == '-help'|| $param == '--help' || $param == '--h'){
		echo "\033[1;33m To scan a target, Use: user$ ".$_SERVER["argv"][0]." https://www.example.com"."\033[0m".PHP_EOL;
		die;
	}
	if(empty($param))
	{
	    echo "\033[1;35m Target URL is required! .. Please use: ".$_SERVER["argv"][0]." https://www.example.com"."\033[0m".PHP_EOL;
	    die;
	}
		  
	if (filter_var($param, FILTER_VALIDATE_URL) === FALSE) {
		print('Not a valid URL .. please use the full format eg: https://example.com')."\n";die;
	}

	$url_handler= parse_url($param);
	if(!isset($url_handler['scheme']) || $url_handler['scheme'] == ''){
		$param = 'https://'.$param;
		$result =get_headers($param.$array[$i],1);
		$res=$http_response_header[0];
		   //print_r($res);
		   if (!strchr($res,'200')) {
			   $param = 'http://'.$param;
		   }
	   }

	$count=1;
		echo "\033[1;31m Started Scanning the Target "."\033[0m";
		echo "....".PHP_EOL."\033[0m";
		$url= $_SERVER["argv"][1].'/';
		$array =   array('wp-admin','wp-content','wp-includes');
		for($i=0;$i<=count($array);$i++){
			$result =get_headers($url.$array[$i],1);
			$response= substr($result[0],9,3);
			$res=($http_response_header[0]);
			if($res == 'HTTP/1.1 404 Not Found' || $res == 'HTTP/1.0 404 Not Found'){
			   if($i == 2){
				 echo "\033[2;33m The Website is not using WordPress ! "."\033[0m\n";
				 exit;
				}
			}
		}
		echo "\033[1;31m Dumping the users ..."."\033[0m".PHP_EOL;
		//sleep(1);
		echo "-------------------------------------------\n";
		$mask = "|%5.5s ||%-30.40s ||\n";
		printf($mask, 'ID', '  Users');
		echo "-------------------------------------------\n";
		//sleep(1);
		for ($j = 1; $j <= 22; $j++){
			$response=get_headers($url.'/?author='.$j,1);
			//$location=array();
			$location = $response['Location'];
			if(is_array($response['Server'])){
			$server= $response['Server'][0];
			}else
			$server= $response['Server'];
			$lang= $response['X-Powered-By'];
			$location = str_replace($url.$j,'', $location);
			//preg_match('*?/author/(.*?)/', $location);
			if(is_array($location))
			{
			  $location = $location[1];	
			}
			$author=explode('/author/', $location);
			// print_r($location);
			// print_r($author);
			$user = str_replace('/','',$author[1]);
		   //	print_r($author);
			
			if (isset($user) && !empty($user)) {
				$count1[]=$count++;
			}

			if(!empty($user)){
			    printf($mask, $j, $user);	
			}
			if($j > 21 && $user == ''){
				printf($mask, '', "Couldn't fetch the users!");	
			}
		}
		
		//sleep(1);
		echo "-----------------------------------------------\n";
		echo "Number of users Found  ".count($count1).PHP_EOL;
		echo "Server Found  ".$server.PHP_EOL;
		if(!empty($lang)){
		echo "Technology: ".trim($lang[1]).PHP_EOL;
		}
		echo "\033[1;31m Please wait ..."."\033[0m".PHP_EOL;

	    $array =   array('wp-admin','wp-content','wp-includes','readme.html');
		$j=0;
		$html1 = file_get_contents($url."readme.html");
		$res=($http_response_header[1]);
		if($res == 'HTTP/1.1 404 Not Found'){
		 $html1 = file_get_contents($url);
		}
		for($i=0;$i<=count($array);$i++){
			$result =get_headers($url.$array[$i],1);
			$response= substr($result[0],9,3);
			$readme = file_get_contents($url.'readme.html');
			$res=($http_response_header[1]);
			if($res == 'HTTP/1.1 404 Not Found'){
				$html1 = file_get_contents($url);
			} 
			  if ($j == 1) {
				//check readme	
				if(preg_match("/version/i",$readme)){
					$html = file_get_contents($url."readme.html");
					# Create a DOM parser object
					$dom = new DOMDocument();
					# loadHTML might throw because of invalid HTML in the page.
					$dom->loadHTML($html);
					$ve=($dom->getElementById('logo')->textContent);
					$version = str_replace('Version', '', $ve);
					// echo $version;
					$version_result[]=$version;
				}
				  //check home page	
				if(preg_match("/wp/i",$html1)){		
					 $html = file_get_contents($url);	
				   //$html = '<meta name="generator" content="WP 4.5"/>';
			    	preg_match_all( '#<meta name="generator" .*?content="(.*?)"\s*/>#i', $html, $results );
				   if (isset($results)) {
				    $full_version = str_replace('WordPress','',$results[1][0]);
				    // if(!empty($full_version)){
				        $version_result[]= trim($full_version);
					//  }
					}
					preg_match( '#/themes/(.*?)/#i', $html, $results );
					echo "Theme name: ".$results[1]."\n";
					preg_match_all( '#/plugins/(.*?)/#i', $html, $results );
					$data = ($results[0]);
					$plugins = array_unique($data);	
					$array = array('/plugins/',"/");
					 for($i=0;$i<=count($plugins);$i++){
						$plugin_name = str_replace($array,'',$plugins);
						if(!empty($plugin_name[$i])){
						echo "Pluging found: ".$plugin_name[$i]."\n";
						}
					}
					
				}
				//check  RSS feed page	
				if(preg_match("/wp/i",$html1)){
					$html= file_get_contents($url.'/feed');
					$dom = new DOMDocument();
					//$dom->loadXML($html);
					$xml = simplexml_load_string($html, 'SimpleXMLElement', LIBXML_NOCDATA);
					foreach ($xml->channel as $item) {
					//print_r($item->generator);
					$version = str_replace('https://wordpress.org/?v=','', $item->generator[0]);
  					  if(!empty($version)){
						$version_result[]=trim($version);
					 }
					}

					$full_version=trim($version_result[0]);
					if (!empty($full_version)) {
						$version1[]=$full_version[0];
					}
				}
					
				if(empty($version1)){
					$version1=trim($version_result[1]);
				}
				if(empty($version_result[0])){
					$version_result[0] = $version1;
				}
				$final1 = trim($version_result[1] != '' ? $version_result[1] : $version_result[0]); /// change here same same
				if(empty($final1))
				{
					//detection from feed/rdf
					$data=file_get_contents("$url/feed/rdf");
					preg_match_all( '#".*/?v=(.*?)"\s* #i', $data, $results );
					$data=$results[0];
					$full_version = str_replace('"https://wordpress.org/?v=','',$data[0]);
					$full_version = str_replace('"','',$full_version);
					$final1= strip_tags($full_version);
				}
				if(empty($final1)){
					// detetction from atom .. piece of shit this
					$data1=file_get_contents($url."/feed/atom/");
					preg_match( '/<generator uri="(.*?)" ?version="(.*?)"/U', $data1, $results );
					$final1 = strip_tags($results[2]);
				}
				if(empty($final1)){
					$data1=file_get_contents($url."/wp-links-opml.php");
					preg_match_all( '/generator="(.*?)" -->/U', $data1, $results );
					$data=($results[1]);
					$final1 = str_replace('WordPress/','',$data);
				}
				$final = str_replace('.','',$final1);
	
			}// end j++ 

			$j++;
		} 
			
				$url_1= ("https://www.wphunter.co/api/?wp=".trim($final));
				$data = sendRequest($url_1);
				$result = json_decode($data);
				echo "\033[0;34m Website is using WordPress Version: ".$final1."\033[0m\n";
				echo "\033[1;33m Vulnerabilities Found affecting this version: "."\033[0m\n";
				//	echo "+--------------------------------------------------------------------------------------------------------------------+\n";
				//	$mask = "+%5.5s | %-30.80s | %-10.10s| %-10.100s | %-80.60s +\n";
				//	printf($mask, 'ID', 'Title','CVE','Resources','Published');
				//echo "+----------------------------------------------------------------------------------------------------------------------+\n";
				$version=$final/10;
				//print_r($result->{'3.9'}->release_date);
				//print_r($result->{'3.9'}->changelog_url);
				$data = count($result->{$final1}->vulnerabilities);
				//print_r($result->$final1->vulnerabilities);die;
				//echo $data;
				for($i=0;$i<=$data;$i++){
				//print_r($result->{$final1}->vulnerabilities[$i]);
				  $vuln_id = $result->{$final1}->vulnerabilities[$i]->id;
				  $title = $result->{$final1}->vulnerabilities[$i]->title;
				  $created_at = $result->{$final1}->vulnerabilities[$i]->created_at;
				  $updated_at = $result->{$final1}->vulnerabilities[$i]->updated_at;
				  $published_date = $result->{$final1}->vulnerabilities[$i]->published_date;
				  $cve = $result->{$final1}->vulnerabilities[$i]->references->cve;
				if(is_array($cve)){
						foreach($cve as $ks => $t ):
						$cve[]=$t;
						endforeach;
				}
				$url = $result->{$final1}->vulnerabilities[$i]->references->url;
				if(is_array($url)){
						foreach($url as $ks => $t):
						$url[]=$t.PHP_EOL;
						endforeach;
				}
				$exploitdb = $result->{$final1}->vulnerabilities[$i]->references->exploitdb;
				if(is_array($exploitdb)){
						foreach($exploitdb as $ks => $t ):
							$exploitdb[]=$t;
						endforeach;
				}
				$metasploit = $result->{$final1}->vulnerabilities[$i]->references->metasploit;
				if(is_array($metasploit)){
						foreach($metasploit as $ks => $t ):
							$metasploit[]=$t;
						endforeach;
				}
				$vuln_type= $result->{$final1}->vulnerabilities[$i]->vuln_type;
				$fixed_in = $result->{$final1}->vulnerabilities[$i]->fixed_in;
				if(is_array($cve)){
					$cve = array_unique($cve);
				}
				if(is_array($url)){
					$url = array_unique($url);
				}
				if(is_array($metasploit)){
					$metasploit = array_unique($metasploit);
				}
				if(is_array($exploitdb)){
					$exploitdb  = array_unique($exploitdb);
				}
				if(empty($published_date)){
					$published_date='NULL';
				}
				// if (empty($fixed_in)) {
				// 	$fixed_in='Not Patched';
				// }
				if(!empty($title)){
				  echo "\033[1;31m [+] Vulnerability:  $title "."\033[0m"."\n";
				}
				//echo "[+] ID: ".$vuln_id."\n";	
				if(!empty($url)){
			      foreach($url as $urls){
				  echo "[+] Reference: ".$urls."\n";	
				  }
				}
				if(!empty($cve)){
				  echo "[+] CVE: ".$cve[0]."\n";	
				}
				//echo "[+] Fixed in: ".$fixed_in."\n";	
				// if(!empty($fixed_in)){
				//   echo "\033[1;32m [+] Fixed in:  $fixed_in "."\033[0m"."\n\n";
				// }	
			}	
			$url = $_SERVER["argv"][1].'/';
			$d = sendRequest("https://www.wphunter.co/api/list.php?site=".$url);
			$s = json_decode($d,TRUE);
			echo "\033[1;34m [+] Checking the website from malware and blacklist domain"."\033[0m"."\n\n";
			echo "[+] Kaspersky: ".$s["scans"]['Kaspersky']['result']."\n";
			echo "[+] BitDefender: ".$s["scans"]['BitDefender']['result']."\n";
			echo "[+] ESET: ".$s["scans"]['ESET']['result']."\n";  
			echo "[+] Avira: ".$s["scans"]['Avira']['result']."\n";  
			echo "[+] Google Safebrowsing: ".$s["scans"]['Google Safebrowsing']['result']."\n";  
			echo "[+] OpenPhish: ".$s["scans"]['OpenPhish']['result']."\n"; 
			echo "[+] DNS8: ".$s["scans"]['DNS8']['result']."\n";
			echo "[+] VX Vault: ".$s["scans"]['VX Vault']['result']."\n";  
			echo "[+] ZDB Zeus: ".$s["scans"]['ZDB Zeus']['result']."\n";  
			echo "[+] ZCloudsec: ".$s["scans"]['ZCloudsec']['result']."\n";  
			echo "[+] PhishLabs: ".$s["scans"]['PhishLabs']['result']."\n"; 
			echo "[+] Zerofox: ".$s["scans"]['Zerofox']['result']."\n"; 
			echo "[+] K7AntiVirus: ".$s["scans"]['K7AntiVirus']['result']."\n"; 
			echo "[+] FraudSense: ".$s["scans"]['FraudSense']['result']."\n";
			echo "[+] Virusdie External Site Scan: ".$s["scans"]['Virusdie External Site Scan']['result']."\n";  
			echo "[+] Quttera: ".$s["scans"]['Quttera']['result']."\n"; 
			echo "[+] AegisLab WebGuard: ".$s["scans"]['AegisLab WebGuard']['result']."\n";  
			echo "[+] MalwareDomainList: ".$s["scans"]['MalwareDomainList']['result']."\n";  
			echo "[+] ZeusTracker: ".$s["scans"]['ZeusTracker']['result']."\n"; 
			echo "[+] zvelo: ".$s["scans"]['zvelo']['result']."\n"; 
			echo "[+] Opera: ".$s["scans"]['Opera']['result']."\n";  
			echo "[+] Certly: ".$s["scans"]['Certly']['result']."\n";  
			echo "[+] G-Data: ".$s["scans"]['G-Data']['result']."\n";  
			echo "[+] C-SIRT: ".$s["scans"]['C-SIRT']['result']."\n";  
			echo "[+] CyberCrime: ".$s["scans"]['CyberCrime']['result']."\n"; 
			echo "[+] SecureBrain: ".$s["scans"]['SecureBrain']['result']."\n";  
			echo "[+] Trustwave: ".$s["scans"]['Trustwave']['result']."\n";  
			echo "[+] CyRadar: ".$s["scans"]['CyRadar']['result']."\n"; 
			echo "[+] Malwarebytes hpHosts: ".$s["scans"]['Malwarebytes hpHosts']['result']."\n";  
			echo "[+] AlienVault: ".$s["scans"]['AlienVault']['result']."\n";  
			echo "[+] Phishtank: ".$s["scans"]['Phishtank']['result']."\n";  
			echo "[+] Phishtank: ".$s["scans"]['Phishtank']['result']."\n";  

		$url = $_SERVER["argv"][1].'/';
		security_header_check($url);
		backup_fuzzer($url);	
		path_disclosure($url);	
	}	

chota();

?>
