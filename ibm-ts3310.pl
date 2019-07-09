#!/usr/bin/perl
use strict;
use POSIX;
my $VERSION="1.0.1";
##
### Vérification des alertes sur une baie IBM Storwize
###
##
my $COLOR_OK="green";
my $COLOR_WARN="yellow";
my $COLOR_KO="red";
#
my $WARN="\&yellow";
my $KO="\&red";
my $OK="\&green";
#
my $COLOR=$COLOR_OK;
#
my $st1="style='margin-left:22px;padding-left:32px;text-align:left'";
#
my $COLUMN="ts3310";
my $TAG=$COLUMN;
my $user="exploit";
my $MSG="";
my $str_time=strftime("%Y-%m-%dT%H:%M:%S",localtime);
my $XYMONCLIENTHOME = defined $ENV{"XYMONCLIENTHOME"} ? $ENV{"XYMONCLIENTHOME"} : "/usr/local/xymon/v4.3.29/client";;
my $XYMONDISP = $ENV{"BBDISP"};
my $BB = defined $ENV{"XYMON"} ? $ENV{"XYMON"} : "$XYMONCLIENTHOME/bin/xymon";
my $str_time=strftime("%Y-%m-%dT%H:%M:%S",localtime);
my @out_html;
my $name=undef;
#
#
#

#print "$XYMONCLIENTHOME/bin/xymongrep --loadhostsfromxymond $TAG \n";


my $cmd="$ENV{JAVA_HOME}/bin/java -jar /home/xymon/TS3310/TS3310CLI.jar -u exploit -p  hendrix546AZE -a ";


foreach my $line (`$XYMONCLIENTHOME/bin/xymongrep --loadhostsfromxymond $TAG`){
	my ($ip,$name,$comment,$key)=split/\s+/,$line;
	my @html;
	my $cmd1 = $cmd . " $name --viewOperatorInterventions";
	my @checkIn;
	push @checkIn,"<table>";
	if(open F,"$cmd1 |"){
		while(my $ldata=<F>){
			next if ($ldata =~ /Number/i);
			next if ($ldata =~ /close|low|cancele/gi);
			#$ldata =~  s/\s+//g;
			chomp $ldata;

			my ($number,$name,$state,$priority,$type,$createTime,$update)=split /,/,$ldata;
			$number =~ s/\s+$//;
			$name =~ s/\s+$//;
			$state =~ s/\s+$//;
			push @checkIn,"<tr><td $st1>$WARN $number</td><td>$name</td><td>$type</td><td>$createTime</td></tr>" if ($number =~ /\d|^\s+\d+/);
		}
		push @checkIn,"</table>";
		if($#checkIn > 3){
			push  @out_html,"<div>$KO Check operator intervention <font color=$COLOR_KO> KO:</font> </div>";
			$COLOR=$COLOR_WARN;
		}else{
			push  @out_html,"<div>$OK Check operator intervention <font color=$COLOR_OK> OK:</font> </div>";
		}
		push @out_html,@checkIn;
		close F;
	}


	my $cmd2=$cmd . " $name --viewLogicalLibraries";
	my @check2_html;
	if(open F,"$cmd2 |"){
		my $color=$COLOR_OK;
		push @check2_html,"<table $st1>";
		while(my $ldata=<F>){
			chomp $ldata;
			next if ($ldata =~ /^\s+name/i);
			$ldata =~  s/\s+//g;
			my ($lib,$mtype,$total_slot,$used_slot,$nb_drive,$nb_tape_in_drive,$encT,$emT,$st)=split/,/,$ldata;	

			if(defined $st){
				my $pused=sprintf("%.f%",(($used_slot + $nb_tape_in_drive)/$total_slot)*100);

				my $st_color= ($st =~ /online/i) ? $COLOR_OK : $COLOR_KO;
				if($pused > 90){
					$st_color=$COLOR_WARN;	
					$color=$COLOR_WARN;
				}
				push @check2_html,"<tr><td>\&$st_color Check library: $lib <font color=$st_color> $st </font></td><tr>"; 
				push @check2_html,"<tr><td $st1>Number slot</td><td>: $total_slot </td><tr>";
				push @check2_html,"<tr><td $st1>Used slot</td><td>: $used_slot </td></tr>";
				push @check2_html,"<tr><td $st1>Number Drives</td><td>: $nb_drive </td></tr>";
				push @check2_html,"<tr><td $st1>%Used</td><td>: <font color=$st_color>$pused </font></td></tr>";
			}
		}
		push @check2_html,"</table>";
		push @out_html,"<div>\&$color Check Libraries : </div>";
		push @out_html,@check2_html;
		close F;
	}

	my $cmd3=$cmd . " $name --viewDriveFirmwareLevels";
	my @check3_html;
	my $color3=$COLOR_OK;
	print "$cmd3 \n";

	if(open F,"$cmd3|"){
		push @check3_html,"<table>";
		my $res=undef;
		while(my $ldata=<F>){	
			next if $ldata =~ /Interface/;
			$ldata =~ s/,//g;
				$ldata =~ s/^\s+//;
			my @T=split/\s+/,$ldata;
			print $ldata;

			my $elementAddress=$T[5];
			my $fw=$T[6];
			my $status=$T[7];
			my $serial=$T[1];
			my $lib=$T[2];
			my $type=$T[3];
			if($ldata =~ /offline/i){
				$color3=$COLOR_WARN;
				$res=1;
				if($COLOR ne $COLOR_OK){
					$COLOR=$COLOR_WARN;
				}
			}else{
				$color3=$COLOR_OK;
			}
			push @check3_html,"<tr><td $st1>\&$color3 $elementAddress</td><td>$type</td><td>$lib</td><td>$fw</td><td>$serial</td><td><font color=$color3>$status</font></td></tr>";	
		}
		$color3= defined $res ? $COLOR_WARN : $COLOR_OK;
		if($color3 =~ /$COLOR_OK/){
			push @check3_html,"<tr><th>Element Adress</th><th>Type</th><th>Firmware</th><th>Drive serial</th><th>Status</th></tr>";
		}
		push @check3_html,"</table>";
		push @out_html,"<div>\&$color3 Drive summaray: </div>"; 
		push @out_html,@check3_html;
		close F;
	}


	my @check4_html;
	push @check4_html,"<table>";
	my $cmd4=$cmd . "$name --viewCleaningCartridges";
	my $color4=$COLOR_OK;	
	print "$cmd4 \n";
	if(open F,"$cmd4 |"){
		while(my $ldata=<F>){
			next if($ldata =~ /^Vol/i);
			next if $ldata =~ /^\s+$/;
			$ldata=~ s/^\s+//g;
			my @T=split/\s+/,$ldata;
			my $rem=$T[4];
			my $vsn=$T[0];
			print $ldata;
			if(defined $rem && defined $vsn){
				my $color=$COLOR_OK;
				if($rem <10){
					if($COLOR eq $COLOR_OK){
						$COLOR=$COLOR_WARN;
						$color=$COLOR_WARN;
						$color4=$COLOR_WARN;
					}
				}
				push @check4_html,"<tr><td $st1>$vsn</td><td><font color=$color>remainin: $rem </font></td><tr>";
			}
		}
		push @check4_html,"<table>";
		my $res_color=$color4 ne $COLOR_OK ? $COLOR_WARN : $COLOR_OK;
		my $res_text=$color4 ne $COLOR_OK ? "KO" : "OK";
		push @out_html,"<div>\&$res_color Checks Cleaning Cartridges: <font color=$res_color>$res_text</font></div>";
		push @out_html,@check4_html;
		close F;
	}


	my @check5_html,"<table>";
	my $cmd5=$cmd . "$name --viewIOStation";
	my $color5=$COLOR_OK;
	print "$cmd5 \n";
	if(open F,"$cmd5 |"){
		while(my $ldata=<F>){	
			print $ldata;
			$ldata =~ s/\s+//g;
			my ($vsn,$lib,$med,$loc)=split/,/,$ldata;
			if($ldata =~ /un/i){
				$color5=$COLOR_WARN;
				if($COLOR eq $COLOR_OK){
					$COLOR=$COLOR_WARN;
				}
				push @check5_html,"<tr><td $st1>\&$color5 Tape: $vsn</td><td>$lib</td><td></tr>";	
			}
		}
		@check5_html,"</table>";
		my $res_color=$COLOR_OK;
		my $res_txt="OK";
		if($#check5_html > 0){
			$res_color=$COLOR_OK;
			$res_txt="KO";
		}
		push @out_html,"<div>\&$color5 Check I/O Station: <font color=$res_color>$res_txt</font></div>";
		push @out_html,@check5_html;
		close F;
	}

	push @out_html,"<br><br><hr>ibm-storwize.pl <a href=\"mailto:pierrejacques.mimifir\@shanaconsulting.org\">Version $VERSION (c) 2018  Pierre-Jacques MIMIFIR</a></br></br>";
	$MSG=join " ",@out_html;
	my $status="status $name.$COLUMN $COLOR\n\n\n";
	my $date=`date`;
	my $cmdx="$BB $XYMONDISP \"$status $date $MSG\"";
	print "$cmdx\n";
	system("$cmdx");
	@out_html=();
	$COLOR=$COLOR_OK;

}

print @out_html;
