#!/usr/bin/perl
use strict;
use strict;
use POSIX;

my $code="check_IO_TS3310.pl";
my $COLOR_WARN="yellow";
my $COLOR_KO="red";

my $COLUMN="IOStation";
my $TAG="ts3310";
my $MSG="";
my $str_time=strftime("%Y-%m-%dT%H:%M:%S",localtime);
my $XYMONCLIENTHOME = defined $ENV{"XYMONCLIENTHOME"} ? $ENV{"XYMONCLIENTHOME"} : "/usr/local/xymon/v4.3.29/client";
my $XYMONDISP = $ENV{"BBDISP"};
my $BB = $ENV{"XYMON"};
my $key="$XYMONCLIENTHOME/etc/keys/storage";
my $str_time=strftime("%Y-%m-%dT%H:%M:%S",localtime);

my $WARN="\&yellow";
my $KO="\&red";
my $OK="\&green";

my $COLOR="green";
my $st1="style=\"margin-left:20px\"";
my $VERSION="1.0.1";

my $tstyle="'border:1px solid blue;background-color:#000066;cellspacing:0px'";

my @media;

foreach my $line (`$XYMONCLIENTHOME/bin/xymongrep --loadhostsfromxymond $TAG`){
	my ($ip,$name,$comment)=split/\s+/,$line;
	print "$ip -- $name\n";
	my $cmd="$ENV{JAVA_HOME}/bin/java -jar /home/xymon/TS3310/TS3310CLI.jar -u exploit -p  hendrix546AZE -a $name";
	$cmd=$cmd . " --viewIOStation";
	my $header=undef;
	my @html;
	push @html,"<table cellspacing='0' cellpadding='0' style='border: 1px solid blue;foreground-color:FFFFCC;cellspacing:0px;cellspadding:0px;width: 650px'><caption style=$tstyle>IBM TS3310 Check IO Station</caption>";
	if (open F,"$cmd |"){
		while(<F>){
			$_=uc $_;
			chomp;
			s/^\s+/ /g;
			my @t=split/,/;
			next if $#t < 3   ;
			if (not defined $header){
				push @html,"<tr><th style=$tstyle>$t[0]</th><th style=$tstyle>$t[1]</th><th style=$tstyle>$t[2]</th></tr>";
				$header=1; 
			}else{
				my $col="green";
				my $color_st=$OK;
				if(($t[1] =~ /unass/i) || ($t[1] =~ /lib/i) ){
					$col=$COLOR_WARN;	
					$color_st=$WARN;
					$COLOR=$COLOR_WARN;
					push @media,$t[0];
				}
				push @html,"<tr><td style=$tstyle>$color_st $t[0]</td><td style=$tstyle><font color='$col'>$t[1]</font></td><td style=$tstyle>$t[2]</td></tr>";
			}
		}
		close F;
	}
	push @html,"</table>";
	if ($#media > -1){
		push @html,"<p style='foreground-color:FFEEFF;'>";
		push @html,"<p>Des medias ont ete trouves dans les guichets du robot.</p>";
		push @html,"<p style='foreground-color:red;'>$WARN Merci d'ouvrir un incident au niveau 2 TSM.</p>";
		push @html,"</p>";
	}
	push @html,"<br><br><hr>$code <a href=\"mailto:pierrejacques.mimifir\@shanaconsulting.org\">Version $VERSION (c)2019 STET Pierre-Jacques MIMIFIR</a></br></br>";
	$MSG=join " ",@html;
	my $status="status $name.$COLUMN $COLOR\n\n\n";
	my $date=`date`;
	my $cmd="$BB $XYMONDISP \"$status $date $MSG\"";
	system("$cmd");
}
