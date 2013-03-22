#!/usr/bin/perl
# ttt - tcpdump top talk parser (formerly iptraf_parser.pl)
# -- adarqui (adarq.org && github.com/adarqui)
use Data::Dumper;
use Socket;
use Getopt::Long;
use POSIX;

%config;
%hash;


# PARSE ARGUMENTS
$config{'condense'} 	= 1;
$config{'iponly'} 		= 0;
$config{'debug'}		= 0;
$config{'summary'}		= 1;
$config{'dots'}			= 0;
$config{'csv'}			= 0;
$config{'columns'}		= 1;
$config{'fortigate'}	= 0;


# setup debug FH
open(OUT, ">", "/dev/null") or die "[x] Can't open /dev/null\n";
my $out = *OUT;


GetOptions (
	'i|in=s'		=> \$config{'in'},
	'o|out=s'		=> \$config{'out'},
	'c|condense'	=> sub { $config{'condense'} = 1; $config{'iponly'} = 0; },
	'ip|iponly'		=> sub { $config{'iponly'} = 1; $config{'condense'} = 0; },
	'sum|summary=i'	=> \$config{'summary'},
	'dots=i'		=> \$config{'dots'},
	'csv=i'			=> \$config{'csv'},
	'col|columns=i'	=> \$config{'columns'},
	'fortigate|fort'=> \$config{'fortigate'},
	'help'			=> \$config{'help'},
	'h'				=> \$config{'help'},
	'debug'			=> \$config{'debug'},
	'd'				=> \$config{'debug'},
);


if($config{'debug'} > 0) {
	$out = *STDOUT;
}


# print $out Dumper(\%config) . "\n";


if($config{'help'} > 0) {
	help();
}
elsif(!$config{'in'}) {
	help("Specify an input file (tcpdump -tt -nn -q -i ... log)");
}


sub help {

	if($_){ 
		print
			"
			Specific error			:	$_
			";
	}

	print 
		"[+] Help:
				--in			:	tcpdump log file: tcpdump -tt -nn -q -i derp0 ...
				--out			:	Output file, stdout by default
				--condense		:	Condense traffic table
				--iponly		:	Maximum condensed data, only keep track of src/dst ip pairs
				--summary		:	Print (or not) out a summary of the flows / top talkers
				--columns		:	Print (or not) output in columns format
				--fortigate		:	Process the input log as a fortigate diag sniffer packet log
				--debug			:	Print out debugging information	
				--help			:	This menu
		\n";

	exit(0);
}



my $input_fh;

	open( $input_fh, "<", $config{'in'} ) || die "[x] Can't open iptraf.log: $!";	
	my @lines = <$input_fh>;
	@data{'raw'} = join('', @lines);

parse_line(@lines);

clean_results();
print_results();


sub compare_ip {
	my $src = $_[0];
	my $dst = $_[1];

	my $ip_src = inet_aton($src);
	my $ip_dst = inet_aton($dst);

	my $ip_src = (unpack "N", $ip_src);
	my $ip_dst = (unpack "N", $ip_dst);

	if($ip_src > $ip_dst) {
		return 1; 
	}
	else {
		return 0;
	}
}

sub parse_line {

	my @array = @_;

	foreach(@array) {

		my @sp = split(' ', $_);

		if($config{'fortigate'} > 0) {
			parse_line_fortigate(@sp);
		}
		elsif(@sp[1] eq "IP") {
			parse_line_pcap(@sp);
		}
		else {
			parse_line_iptraf(@sp);
		}
	}
}


sub parse_line_fortigate {

=begin

	0.398084 10.54.1.210.52726 -> 61.129.64.152.53: udp 48
	0.398147 61.254.221.78.52726 -> 61.129.64.152.53: udp 48

	0.405898 61.254.221.68.22 -> 61.135.14.158.4564: 2698548254 ack 2948658105
	0.405904 61.254.221.68.22 -> 61.135.14.158.4564: psh 2698549714 ack 2948658105
	0.405983 61.254.221.68.22 -> 61.135.14.158.4564: psh 2698550718 ack 2948658105
	0.406055 61.254.221.68.22 -> 61.135.14.158.4564: psh 2698550834 ack 2948658105
	0.406122 61.254.221.68.22 -> 61.135.14.158.4564: psh 2698550966 ack 2948658105

	0.807723 61.254.221.70.80 -> 111.87.228.66.52528: psh fin 4294708591 ack 380200182

	0.381555 10.54.11.153.3684 -> 10.1.1.115.1270: syn 3951706041

	0.654580 10.54.1.220.53 -> 10.60.0.206.32309: fin 368871613 ack 1581050557

	0.421047 61.254.221.68 -> 211.38.198.189: ip-proto-50 276

	2.626389 10.88.0.2 -> 10.54.1.220: icmp: echo request

	0.462227 arp who-has 10.60.0.133 tell 10.60.0.1

	x src.sport -> dst.dport: udp <len>
	x src.sport -> dst.dport: <seq> ack <ack> 
	x src.sport -> dst.dport: psh <seq> ack <ack>
	x src.sport -> dst.dport: psh fin <seq> ack <ack>
	x src.sport -> dst.dport: syn <seq>
	x src.sport -> dst.dport: fin <seq> ack <ack>
	x src -> dst: ip-proto-50 <len>
	x src -> dst: icmp
	x arp


	12.042087 10.88.0.11.50194 -> 10.54.1.14.41108: ack 803342372

	x src.sport -> dst.dport: ack <ack> <- nothing


=end
=cut


	undef @sp;
	my @sp = @_;

	undef %pkt;
	my %pkt;

	if(@sp[1] eq "arp" || @sp[1] eq "Ether")  { return; }
 
    $pkt{'src'} = @sp[1];
    $pkt{'dst'} = @sp[3];

    $pkt{'dst'} =~ tr/[:;]//d;

	if(@sp[4] eq "udp") {
		$pkt{'bytes'} = @sp[@sp-1];
		$pkt{'proto'} = "UDP";
	}
	elsif (@sp[4] eq "icmp:") {
		$pkt{'proto'} = "ICMP";
		$pkt{'bytes'} = 1;
	}
	elsif (@sp[4] eq "ip-proto-50") {
		$pkt{'proto'} = "IPSEC";
		$pkt{'bytes'} = @sp[@sp-1];
	}
=begin
	0.405898 61.254.221.68.22 -> 61.135.14.158.4564: <seq> ack <ack>
    0.405904 61.254.221.68.22 -> 61.135.14.158.4564: psh <seq> ack <ack>
	0.807723 61.254.221.70.80 -> 111.87.228.66.52528: psh fin <seq> ack <ack>
    0.381555 10.54.11.153.3684 -> 10.1.1.115.1270: syn <seq>
	0.654580 10.54.1.220.53 -> 10.60.0.206.32309: fin <seq> ack <ack>
	0.042087 10.88.0.11.50194 -> 10.54.1.14.41108: ack <ack>
	0		1					2	3				4	5	6
=end
=cut
	# TCP processing
	elsif (@sp[4] eq "syn") {
		$pkt{'flag'} = "syn";
		$pkt{'seq'} = @sp[5];
		$pkt{'proto'} = 'TCP';
	}
	elsif (@sp[4] eq "ack") {
		return;
	}
	elsif (@sp[4] eq "psh" && @sp[5] eq "fin") {
		$pkt{'flag'} = "seq";
		$pkt{'seq'} = @sp[6];
		$pkt{'proto'} = 'TCP';
	}
	elsif (@sp[4] eq "psh") {
		$pkt{'flag'} = "seq";
		$pkt{'seq'} = @sp[5];
		$pkt{'proto'} = 'TCP';
	}
	elsif (@sp[4] eq "fin" || @sp[4] eq "rst") {
		$pkt{'flag'} = "seq";
		$pkt{'seq'} = @sp[5];
		$pkt{'proto'} = 'TCP';
	}
	elsif (@sp[5] eq "ack") {
		$pkt{'flag'} = "seq";
		$pkt{'seq'} = @sp[4];
		$pkt{'proto'} = 'TCP';
	}
	else {
		return;
	}

	if($pkt{'proto'} == "UDP" || $pkt{'proto'} == "TCP") {

		@asrcp = split('\.', $pkt{'src'});
		@adstp = split('\.', $pkt{'dst'});

		$pkt{'sport'} = @asrcp[4];
		$pkt{'dport'} = @adstp[4];

		$pkt{'src'} = @asrcp[0].".".@asrcp[1].".".@asrcp[2].".".@asrcp[3];
		$pkt{'dst'} = @adstp[0].".".@adstp[1].".".@adstp[2].".".@adstp[3];;
	}

	$pkt{'ts'} = @sp[0];

	#print Dumper (%pkt) . " : " . Dumper (@sp) . "\n";

	parse_line_obj(%pkt);
}


sub parse_line_pcap {
=begin
        1361083134.289546 IP 10.200.1.18.54601 > 10.200.1.1.22: tcp 64
        1361083134.289610 IP 10.200.1.1.22 > 10.200.1.18.54601: tcp 32
        1361083134.291162 IP 10.200.1.18.54601 > 10.200.1.1.22: tcp 0
        1361083137.706761 IP 10.200.1.10.54013 > 10.200.1.1.1514: UDP, length 233
        1361083137.706803 IP 10.200.1.10.54013 > 10.200.1.1.1514: UDP, length 249
        1361083139.709033 IP 10.200.1.10.54013 > 10.200.1.1.1514: UDP, length 257
        1361115505.014528 IP 10.200.1.1 > 10.200.1.6: ICMP echo request, id 3104, seq 4, length 64
        1361115505.041035 IP 10.200.1.6 > 10.200.1.1: ICMP echo reply, id 3104, seq 4, length 64
=end
=cut

	my @sp = @_;

	undef %pkt;
	my %pkt;

	$pkt{'bytes'} = @sp[@sp-1];
    $pkt{'src'} = @sp[2];
    $pkt{'dst'} = @sp[4];
    $pkt{'proto'} = uc(@sp[5]);
	$pkt{'proto'} =~ tr/[;:,]//d;

	$pkt{'dst'} =~ tr/[:;]//d;

	if($pkt{'proto'} == "udp" || $pkt{'proto'} == "tcp") {

		@asrcp = split('\.', $pkt{'src'});
		@adstp = split('\.', $pkt{'dst'});

		$pkt{'sport'} = @asrcp[4];
		$pkt{'dport'} = @adstp[4];

		$pkt{'src'} = @asrcp[0].".".@asrcp[1].".".@asrcp[2].".".@asrcp[3];
		$pkt{'dst'} = @adstp[0].".".@adstp[1].".".@adstp[2].".".@adstp[3];;
	}

	$pkt{'ts'} = @sp[0];

	parse_line_obj(%pkt);
}


sub parse_line_iptraf {

=begin
         Sat Feb  9 01:31:58 2013; ICMP; eth0; 76 bytes; from 192.168.1.50 to 68.123.143.121; time excd 
         Sat Feb  9 01:28:28 2013; UDP; eth0; 417 bytes; from 199.193.251.108:53648 to 192.168.1.50:1194 
         Sat Feb  9 01:29:14 2013; TCP; eth0; 84 bytes; from 192.168.1.50:22 to 192.168.1.101:36429; first

         Tue Feb 12 12:46:12 2013; TCP; eth0; 1281 bytes; from 199.193.251.107:80 to 192.168.1.50:54919; FIN sent; 123 packets, 181379 bytes, avg flow rate 1451.00 kbits/s 15 - packets sent * 17 - packet size
         

         Wed Feb 13 01:15:41 2013; TCP; Connection 192.168.56.100:443 to 141.212.121.40:54622 timed out, 0 packets, 0 bytes, avg flow rate 0.00 kbits/s; opposite direction 240 packets, 10320 bytes, avg flow rate 0.00 kbits/s"}]}
         * Wed Feb 13 02:04:09 2013; TCP; Connection 192.168.56.100:403 to 216.152.252.211:63668 timed out, 0 packets, 0 bytes, avg flow rate 0.00 kbits/s; opposite direction 342 packets, 17328 bytes, avg flow rate 0.00 kbits/
         * 6 - Connection
         * 25 - packet bytes
         * 28 - flow
=end
=cut

	my @sp = @_;

	undef %pkt;
	my %pkt;

	$pkt{'bytes'} = @sp[7];
	$pkt{'src'} = @sp[10];
	$pkt{'dst'} = @sp[12];
	$pkt{'proto'} = uc(@sp[5]);

	if($pkt{'proto'} == "udp" || $pkt{'proto'} == "tcp") {

		@asrcp = split(':', $pkt{'src'});
		@adstp = split(':', $pkt{'dst'});

		$pkt{'sport'} = @asrcp[1];
		$pkt{'dport'} = @adstp[1];

		$pkt{'src'} = @asrcp[0];
		$pkt{'dst'} = @adstp[0];
	}     

	$pkt{'src'} =~ tr/[:;]//d;
	$pkt{'dst'} =~ tr/[:;]//d;
	$pkt{'sport'} =~ tr/[:;]//d;
	$pkt{'dport'} =~ tr/[:;]//d;

	$pkt{'ts'} = @sp[0];
	
	parse_line_obj(%pkt);
}


sub parse_line_obj {

		undef %pkt;
		my (%pkt) = @_;

		if($pkt{'proto'} ne 'ICMP' && $pkt{'proto'} ne 'TCP' && $pkt{'proto'} ne 'UDP' && $pkt{'proto'} ne 'IPSEC') { 
			return 0;
		}

		my $cmp = compare_ip($pkt{'src'}, $pkt{'dst'});

		if($cmp < 1) { 
			$left = $pkt{'src'};
			$right = $pkt{'dst'};
			$leftp = $pkt{'sport'};
			$rightp = $pkt{'dport'};
		}
		else {
			$left = $pkt{'dst'};
			$right = $pkt{'src'};
			$leftp = $pkt{'dport'};
			$rightp = $pkt{'sport'};
		}


		$key = $pkt{'proto'} . "," . $left . "," . $leftp . "," .  $right . "," . $rightp;

		my $total_bytes = 0;
		my $first;

		my $hash_elm = $hash{$key};
		if($hash_elm) {

			if($config{'fortigate'} > 0 && $pkt{'proto'} eq "TCP") {
			# fortigate dump

				undef $side;
				my $side;
				if($pkt{'src'} eq $hash{$key}{'src'}) {
					$side = 'src';
				} else {
					$side = 'dst';
				}

				if($hash{$key}{ $side . "_seq" } == 0) {
					$hash{$key}{ $side . "_seq" } = $pkt{'seq'};
				} else {
					if($hash{$key}{$side . '_seq'} ne $pkt{'seq'}) {
						undef $tot;
						my $tot = $hash{$key}{'total_bytes'} + ($pkt{'seq'} - $hash{$key}{$side . '_seq'});

						$hash{$key}{$side . '_seq'} = $pkt{'seq'};

						# Alien technology
						if($hash{$key}{'total_bytes'} < 0) {
							$hash{$key}{ 'backup_total_bytes '} = $hash{$key}{ 'total_bytes' } + $hash{$key}{'backup_total_bytes'};
							$hash{$key}{'total_bytes'} = 0 ;
						}
						else {
							$hash{$key}{'total_bytes'} = $tot;
						}
					}
					else {
						# duplicate (could be related to listening on multiple interfaces
					}
				}
			}
			else {
			# tcpdump/iptraf
				$total_bytes = $hash{$key}{"total_bytes"} + $pkt{'bytes'};
				$hash{$key}{ "total_bytes" } =  $total_bytes ;
			}
			$hash{$key}{ "ts_e" } = $pkt{'ts'};
		}
		else {
		# new session

			$hash{$key}{ "first_source" } = $pkt{'src'};
			$hash{$key}{ "src" } = $pkt{'src'};
			$hash{$key}{ "dst" } = $pkt{'dst'};
			$hash{$key}{ "sport" } = $pkt{'sport'};
			$hash{$key}{ "dport" } = $pkt{'dport'};
			$hash{$key}{ "ts_b" } = $pkt{'ts'};

			$hash{$key}{ "src_seq" } = 0;
			$hash{$key}{ "dst_seq" } = 0;

			if($config{'fortigate'} > 0 && $pkt{'proto'} eq "TCP") {

				undef $side;
				my $side;
				if($pkt{'src'} eq $hash{$key}{'src'}) {
					$side = 'src';
				} else {
					$side = 'dst';
				}

				$hash{$key}{ $side . "_seq" } = $pkt{'seq'};
				$hash{$key}{ "total_bytes" } = 0;
			} else {
				$hash{$key}{ "total_bytes" } = $pkt{'bytes'};
			}

			# Alien technology
			$hash{$key}{ "backup_total_bytes" } = 0;

		}


		$hash{$key}{'proto'} = $pkt{'proto'};

		$tx_to_src = $hash{$key}{"tx_to_src"};
		$tx_to_dst = $hash{$key}{"tx_to_dst"};

		if($pkt{'src'} eq $left) {
			$tx_to_dst = $tx_to_dst + $pkt{'bytes'};
			$hash{$key}{ "tx_to_dst"} = $tx_to_dst ;
		}
		else {
			$tx_to_src = $tx_to_src + $pkt{'bytes'};
			$hash{$key} {"tx_to_src" }= $tx_to_src ;
		}
}

# create unique string hashes of:
#  icmp: src,dst
#  tcp: src,sport,dst,dport
#  udp: src,sport,dst,dport
#
# values of each hash include:
#  bytes=> ...

sub clean_results {

%hash_new;

	foreach $key (keys %hash) {
		my $elm = $hash{$key};

		my @fields = split(',', $key);
		# proto,src,srcport,dst,dstport
		my $first_source = $hash{$key}{"first_source"};


		if($config{'condense'} > 0) {

			if($first_source) {

				if($first_source eq @fields[1]) {
					@fields[2] = '0';
				}
				else {
					@fields[4] = '0';
				}

			}

			my $new_key = join ",", @fields;	

			my $hash_existing = $hash_new{$new_key};
			if($hash_existing) { 
				$hash_new{$new_key}{'total_bytes'} = $hash_new{$new_key}{'total_bytes'} + $hash{$key}{'total_bytes'};
				$hash_new{$new_key}{'tx_to_src'} = $hash_new{$new_key}{'tx_to_src'} + $hash{$key}{'tx_to_src'};
				$hash_new{$new_key}{'tx_to_dst'} = $hash_new{$new_key}{'tx_to_dst'} + $hash{$key}{'tx_to_dst'};
			}
			else {
				$hash_new{$new_key} = $elm;
			}

		}
		elsif ($config{'iponly'}) {

			@fields[2] = ' ';
			@fields[4] = ' ';

			my $new_key = join ",", @fields;
			my $old = $hash_new{$new_key}{'total_bytes'};
			$hash_new{$new_key} = $elm;

			$hash_new{$new_key}{'sport'} = '';
			$hash_new{$new_key}{'dport'} = '';

			$hash_new{$new_key}{'total_bytes'} = $hash_new{$new_key}{'total_bytes'} + $old;

		}
		else {
			$hash_new{$key} = $elm;
		}
	}

%hash = %hash_new;

}


sub print_results {

#	print Dumper(\%hash);


	if($config{'summary'} == 0) {
		foreach $key (keys %hash) {
			my $sport;
			my $dport;
			if($hash{$key}{'proto'} eq "TCP" || $hash{$key}{'proto'} eq "UDP") {
				$sport = "." . $hash{$key}{'sport'} . " ";
				$dport = "." . $hash{$key}{'dport'} . " ";
			}

			# 1361083139.709033 IP 10.200.1.10.54013 > 10.200.1.1.1514: UDP, length 257
			print "$hash{$key}{'ts_b'} IP $hash{$key}{'src'}$sport > $hash{$key}{'dst'}$dport $hash{$key}{'proto'} length $hash{$key}{'total_bytes'}\n";

			if($hash{$key}{'ts_e'}) {
				print "$hash{$key}{'ts_e'} IP $hash{$key}{'src'}$sport > $hash{$key}{'dst'}$dport $hash{$key}{'proto'} length 0\n";
			}
		}
	}
	else {
	# summary
		print "Flows:\n";

		$z = "";
		if($config{'csv'} > 0) {
			$comma = ',';
		} else {
			$comma = '';
		}

		$num = 1;

		#
		# i ! <3 perl
		#

		if($config{'columns'} == 1) {
			$z = sprintf ("%-10s %-15s %-10s %-15s %-10s %-15s %-10s %-10s\n" ,  
				"Index" , "Total_Bytes", "Protocol", "Src", "sPort", "Dst", "dPort", "Time (s)");
		}

		foreach $key (sort { ($hash{$b}->{total_bytes} <=> $hash{$a}->{total_bytes}) } keys %hash) {
			if($hash{$key}{'ts_e'} == 0 || $hash{$key}{'ts_b'} == 0) {
				$t = 0;
			}
			else {
				$t = $hash{$key}{'ts_e'} - $hash{$key}{'ts_b'};
				$t = ceil($t);
			}

			if($config{'columns'} == 0) {
				$z = $z . "$num $comma total_bytes=$hash{$key}{'total_bytes'} $comma proto=$hash{$key}{'proto'} $comma src=$hash{$key}{'src'} $comma dst=$hash{$key}{'dst'} $comma dport=$hash{$key}{'dport'} $comma time=$t\n";
			} else {
				$z = $z . sprintf("%-10s %-15s %-10s %-15s %-10s %-15s %-10s %-10s\n", 
					$num, $hash{$key}{'total_bytes'}, $hash{$key}{'proto'}, 
					$hash{$key}{'src'}, $hash{$key}{'sport'}, $hash{$key}{'dst'}, $hash{$key}{'dport'}, $t);
			}

			$num = $num + 1;
		}
		
		if($config{'dots'} == 1) {
=begin
			@expanded_lines = expand($z);
			print @expanded_lines;
=end
=cut
			$z =~ s/ /\./g;
			$z =~ s/\t/\./g;

		}

		print $z;

	}

}
#:wq
