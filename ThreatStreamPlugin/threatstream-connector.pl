#!/usr/bin/perl
require HTTP::Request;
require LWP::UserAgent;
use strict;
use warnings;
use JSON;
use List::MoreUtils qw(uniq);
use AppConfig qw(:expand :argcount);

#$\ = "\n";

#
#	Configuring properties
#
sub configEnv() {

	my @config_vars = qw{
	  apiuser
	  apikey
	  url
	  result_limit
	  result_format
	  search_type
	  search_type
	  resource
	  queue_name
	  username
	  passwd
	  verbose
	  delay
	  proxy
	  user_agent
	  out_dir
	  clear_files
	  importwatchlistfile_path
	};
	my $conf = AppConfig->new(
		{
			CASE     => 1,
			PEDANTIC => 1,
			GLOBAL   => {
				ARGCOUNT => ARGCOUNT_LIST,
				EXPAND   => EXPAND_VAR,
			},
		},
		@config_vars
	);
	$conf->file('./threatstream-connector.properties');
	return $conf;
}

#
#	Configuring variables
#
our $conf          = configEnv();
our $apiuser       = @{ $conf->apiuser() }[0];
our $apikey        = @{ $conf->apikey() }[0];
our $query_api_url = @{ $conf->url() }[0];
our $resource      = @{ $conf->resource() }[0];
our $limit         = @{ $conf->result_limit() }[0];
our $format        = @{ $conf->result_format() }[0];
our @search_types  = @{ $conf->search_type() };
our $verbose       = @{ $conf->verbose() }[0];
our $list          = @{ $conf->queue_name() }[0];
our $username      = @{ $conf->username }[0];
our $passwd        = @{ $conf->passwd }[0];
our $proxy         = @{ $conf->proxy() }[0];
our $user_agent    = @{ $conf->user_agent() }[0];
our $out_dir       = @{ $conf->out_dir }[0];
our $clear_files   = @{ $conf->clear_files }[0];
our $delay         = @{ $conf->delay }[0];
our $importer      = @{ $conf->importwatchlistfile_path }[0];

#
# logging based on verbose mode
#
sub logs {
	if ( $_[0] <= $verbose ) {
		print localtime(time) . "   [verb=" . $_[0] . "] :\t" . $_[1] . "\n";
	}
}

logs( 2, "var apiuser : " . $apiuser );
logs( 2, "var apikey : " . $apikey );
logs( 2, "var url : " . $query_api_url );
logs( 2, "var resource : " . $resource );
logs( 2, "var result_limit : " . $limit );
logs( 2, "var result_format : " . $format );
logs( 2, "var search_type : " . join( ", ", @search_types ) );
logs( 2, "var verbose : " . $verbose );
logs( 2, "var queue_name : " . $list );
logs( 2, "var username : " . $username );
logs( 2, "var passwd : " . $passwd );
if ($proxy) {
	logs( 2, "var proxy : " . $proxy );
}
logs( 2, "var user_agent : " . $user_agent );
logs( 2, "var out_dir : " . $out_dir );
logs( 2, "var clear_files : " . $clear_files );
logs( 2, "var delay : " . $delay );
logs( 2, "var importwatchlistfile : " . $importer );

#
#	Execution statement
#
sub start_exec {

	logs( 1, "starting execution ..." );

	my $flags = '&limit=' . $limit . '&format=' . $format;
	my $url   =
	    $query_api_url
	  . $resource . '/'
	  . '?username='
	  . $apiuser
	  . '&api_key='
	  . $apikey
	  . $flags;

	my @ip_list;

	for my $type (@search_types) {
		my $json_data = doRequest( $url, $type );
		@ip_list = parseJson( $json_data, @ip_list );
	}

	#removing duplicates and sorting the result
	@ip_list = sort( uniq(@ip_list) );

	generate_file( $list, @ip_list );
}

#
#	post file to nitro
#
sub post_file {

#
# Create the API request string with name/value pairs.
#
	my $file = $_[0];
	my $call = $importer
	  . " -USERNAME '"
	  . $username
	  . "' -PWD '"
	  . $passwd
	  . "' -FSPEC '"
	  . $file;

	logs( 1, "posting file: " . $file );
	logs( 2, " executing importer: " . $call );

	my @args = (
		$importer,
		" -USERNAME '" . $username . "'",
		"-PWD '" . $passwd . "'",
		"-FSPEC '" . $file . "'"
	);

	my $result = capture( $^X, "yourscript.pl", @args );
	logs( 1, "import result: " . $result );

	if ( $clear_files == 1 ) {
		logs( 1, "deleting file: " . $file );
		unlink $file;
	}
}

#
#	creating the result file name
#
sub result_file_name {
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) =
	  localtime(time);
	return $out_dir
	  . sprintf(
		"%04d%02d%02d%02d%02d%02d",
		$year + 1900,
		$mon + 1, $mday, $hour, $min, $sec
	  )
	  . '.txt';
}

#
#	writing list to file
#
sub generate_file {

	my $file = result_file_name();
	logs( 1, "creating file: " . $file );

	unless ( open FILE, '>' . $file ) {
		die "\nUnable to create $file\nstopping execution...";
	}
	logs( 1, "total size of " . $list . " : " . scalar( @{ $_[1] } ) );

	print FILE "clear," . $_[0];
	my $lst = "add," . $_[0];
	foreach my $ip ( @{ $_[1] } ) {
		$lst = $lst . ',' . $ip;
	}
	print FILE $lst;

	close FILE;

	post_file($file);
}

#
#	Parsing  query result (json)
#
sub parseJson {
	my $data = JSON->new->utf8->decode( $_[0] );
	my @vect = @{ $data->{objects} };
	foreach my $item (@vect) {
		push( @{ $_[1] }, $item->{srcip} );
	}

	logs( 1, "results found : " . @vect );

	return $_[1];
}

#
#	Requesting ThreatStream
#
sub doRequest {

	my $url = $_[0] . '&itype=' . $_[1];
	logs( 1, "requesting query type: " . $_[1] );
	logs( 2, "requesting -> " . $url );


	my $req = HTTP::Request->new( GET => $url );
	$req->method("GET");

	#	$req->  headers( 'ACCEPT' => 'application/json' ); doesn't work
	my $ua = new LWP::UserAgent( agent => $user_agent );

	if ($proxy) {
		$ua->proxy( [ 'http', 'https' ], $proxy );
	}

	my $resp = HTTP::Response->new;
	$resp = $ua->request($req);

	if ( $resp->code() == 200 ) {

		logs( 2, "response : " . $resp->status_line() );
		logs( 2, "response content : " . $resp->decoded_content() );
		return $resp->decoded_content();
	}
	else {
		print('An error occurred while trying to reach ThreatStream server');
		print( $resp->status_line );
	}
}

#
#	Starting execution
#
sub start() {
	my $i = 1;

	while ($i) {
		start_exec();
		logs( 1, "waiting for " . $delay . " minute(s)." );
		sleep( 60 * $delay );
	}
}

start();

