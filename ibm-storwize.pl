#!/usr/bin/perl
use strict;
use POSIX;
my $VERSION="1.0.1";
##
## Vérification des alertes sur une baie IBM Storwize
##
#
my $COLOR_OK="green";
my $COLOR_WARN="yellow";
my $COLOR_KO="red";

my $WARN="\&yellow";
my $KO="\&red";
my $OK="\&green";

my $COLOR=$COLOR_OK;

my $st1="style=\"margin-left:20px\"";

my $COLUMN="storwize";
my $TAG=$COLUMN;
my $user="exploit";
my $MSG="";
my $str_time=strftime("%Y-%m-%dT%H:%M:%S",localtime);
my $XYMONCLIENTHOME = defined $ENV{"XYMONCLIENTHOME"} ? $ENV{"XYMONCLIENTHOME"} : "/usr/local/xymon/v4.3.29/client";
my $XYMONDISP = $ENV{"BBDISP"};
my $BB = $ENV{"XYMON"};
my $key="$XYMONCLIENTHOME/etc/keys/storage";
my $str_time=strftime("%Y-%m-%dT%H:%M:%S",localtime);
my @out_html;
my $name=undef;

foreach my $l(keys %ENV){
	#print "$l : $ENV{$l} \n";
}

print "$XYMONCLIENTHOME/bin/xymongrep --loadhostsfromxymond $TAG\n";

foreach my $line (`$XYMONCLIENTHOME/bin/xymongrep --loadhostsfromxymond $TAG`){
	chomp;
	$COLOR=$COLOR_OK;
	my ($ip,$name,$comment)=split/\s+/,$line;
	my $cmd1="ssh $name lssystem -delim :";
	print $cmd1 ."\n";
	if(open S,"$cmd1|"){
		my %h;
		while(my $l=<S>){
			my ($key,$value)=split/:/,$l;
			if(defined $key and defined $value){
				$h{$key}=$value;
			}
		}
		close S;
		if(exists $h{product_name}){
			my @xhtml;
			push @xhtml,"<table border=\"1px\">";
			push @xhtml,"<col width=50><col width=90><col width=50><col width=50><col width=50><col width=100>";
			push @xhtml,"<tr><th>Product</th><th>ID</th><th>Total Capacity</th><th>Vdisk Capacity</th><th>Used Capacity</th><th>Contact</th></tr>";
			push @xhtml,"<tr>";
			push @xhtml,"<td> $h{product_name} </td>";
			push @xhtml,"<td> $h{id} </td>";
			push @xhtml,"<td> $h{total_mdisk_capacity} </td>";
			push @xhtml,"<td> $h{total_vdisk_capacity} </td>";
			push @xhtml,"<td> $h{total_used_capacity} </td>";
			push @xhtml,"<td> $h{email_contact} </td>";
			push @xhtml,"</tr></table>";
			push @out_html,@xhtml;
		}
	}
	$cmd1="ssh $name lsdrive -delim :";
	print "$cmd1 \n";
	if(open S,"$cmd1|"){
		my @xhtml;
		while(my $l=<S>){
			next if( $l =~ /:status:|:online:/);
			my @t=split/:/,$l;
			push @xhtml,"<div st>\&$COLOR_WARN Drive: $t[0] is <font color=$COLOR_WARN>$t[1]</font> : $t[2],$t[3],$t[4] </div>";
			$COLOR=$COLOR_WARN;
		}
		close S;
		my $color = $#xhtml == -1 ? $COLOR_OK : $COLOR_WARN;
		my $text  = $#xhtml == -1 ? "OK" : "Warnings";
		push @out_html,"<div>\&$color Check drives: <font color=$color>$text</font></div>";
		push @out_html,@xhtml;
	}
	$cmd1="ssh $name lsmdisk -delim :";
	print "$cmd1 \n";
	if(open S,"$cmd1|"){
		my @xhtml;
		while(my $l=<S>){
			next if( $l =~ /:status:|:online:/);
			my @t=split/:/,$l;
			push @xhtml,"<div st>\&$COLOR_WARN Mdisk : $t[0] is <font color=$COLOR_WARN>$t[1]</font> : $t[2],$t[3],$t[4] </div>";
			$COLOR=$COLOR_WARN;
		}
		close S;
		my $color = $#xhtml == -1 ? $COLOR_OK : $COLOR_WARN;
		my $text  = $#xhtml == -1 ? "OK" : "Warnings";
		push @out_html,"<div>\&$color Check mdisk: <font color=$color>$text</font></div>";
		push @out_html,@xhtml;
	}

	$cmd1="ssh $name lsnodecanister -delim :";
	print "$cmd1\n";
	if(open S,"$cmd1|"){
		my @xhtml;
		my $text="OK";
		my $color = $COLOR_OK;
		while(my $l=<S>){
			next if( $l =~ /id:name:/);
			my @t=split/:/,$l;
			if($#t > 15){
				if($l =~ /online/){
					push @xhtml,"<div $st1>\&$COLOR_OK Node : $t[1] | WWN:$t[3]| Serial: $t[16]</div>";	
				}else{
					$color=$COLOR_WARN;
					$text="Warnings";
					push @xhtml,"<div $st1>\&$COLOR_WARN Node : $t[1] | WWN:$t[3]| Serial: $t[16]</div>";	
				}		
			}
		}
		close S;
		push @out_html,"<div>\&$color Check node canister: <font color=$color>$text</font></div>";
		push @out_html,@xhtml;
	}

	$cmd1="ssh $name lsmdiskgrp -bytes -delim :";
	print "$cmd1\n";

	if(open S,"$cmd1 |"){
                my @xhtml;
                my $text="";
                my $color = $COLOR_OK;
		my %h;
		my $res=0;
		my $vir=0;
		my $res_color=$COLOR_OK;
                while(my $l=<S>){
			next if($l =~ /id:name/);
			my @t=split/:/,$l;
			$h{virtual_capacity}=$t[8];
			$h{used_capacity}=$t[9];
			$h{real_capacity}=$t[10];
			$h{free_capacity}=$t[7];
			$h{capacity}=$t[5];


			
                }
		if(exists $h{real_capacity}){
			 $vir = ($h{real_capacity}/$h{virtual_capacity})*100;
			 $res=($h{real_capacity}/$h{capacity})*100;
		}

		if($res > 80 and $res < 90){
			$res_color=$COLOR_WARN;
			$color=$COLOR_WARN;
		}elsif($res > 90){
			$res_color=$COLOR_KO;
			$color = $COLOR_KO;
		}

		my $vir_color=$COLOR_OK;
		my $vir_text=sprintf("%-2.f%",$vir);
		my $text=sprintf("%-2.f%",$res);
		if($vir > 80 and $res < 90){a
			$res_color=$COLOR_WARN;
			$vir_color=$COLOR_WARN;
		}elsif($vir > 90){
			$res_color=$COLOR_KO;
			$vir_color=$COLOR_KO;
		}
		push @xhtml,"<div $st1>\&$vir_color Virtual storage used: <font color=$vir_color>$vir_text</font></div>";
		push @xhtml,"<div $st1>\&$vir_color Real storage used   : <font color=$color>$text</font></div>";

                close S;
		my $res_text=$res_color eq $COLOR_OK ? "OK:" : "Warnings:";
                push @out_html,"<div>\&$color Check storage used capacity: <font color=$res_color>$res_text</font></div>";
                push @out_html,@xhtml;

		my @data;
		push @data,"\n\n[capacity.storwize.rrd]";
		push @data,"DS:real_capacity:GAUGE:300:0:U $h{real_capacity}";
		push @data,"DS:virtual_capacity:GAUGE:300:0:U $h{virtual_capacity}";
		push @data,"DS:used_capacity:GAUGE:300:0:U $h{used_capacity}";
		push @data,"DS:capacity:GAUGE:300:0:U $h{capacity}";
		push @data,"DS:free_capacity:GAUGE:300:0:U $h{free_capacity}";
		push @data,"DS:real_used_pct:GAUGE:300:0:U $res";
		push @data,"DS:virtual_used_pct:GAUGE:300:0:U $vir";

		my $DATA=join "\n",@data;
                my $cmd="$BB $XYMONDISP \"data $name\.trends $DATA\" ";
                #print "Capacity data to send : $cmd\n";
                system("$cmd");

        }

	$cmd1="ssh $name lshost -nohdr -delim :";
	print "$cmd1 \n";
	if(open F,"$cmd1 |"){
		my @html;
		my @res;
		while (my $l=<F>){
			if($l =~ /^\d/){
				if($l =~ /degra/){
					my @t=split/:/,$l;
					push @html,"<div $st1>$WARN $t[1]:<font color=\"$COLOR_WARN\">$t[4]</font></div>";
				}
			}
		}
		close F;
		my $txt="OK";
		my $res_color=$COLOR_OK;
		if($#html > -1){
			$txt="Warnings !";
			$res_color=$COLOR_WARN;;
			if($COLOR  =~ /$COLOR_OK/){
				$COLOR=$COLOR_WARN;
			}
		}


		push @res,"<div>\&$res_color Check hosts access:<font color=\"$res_color\">$txt</font></div>";
		push @res,@html;
		push @out_html,@res;
	}

	$cmd1="ssh $name lseventlog -alert yes -message no -fixed no -nohdr -delim :";
	print "$cmd1\n";
	if(open S,"$cmd1 |"){
		my @html;
		my @res;
		while(my $l=<S>){
			my @T=split/:/,$l;
			push @html,"<div $st1>$KO $T[9] $T[10]: <font color=$COLOR_KO>$T[11]</font></div>";
			$COLOR=$COLOR_KO;
		}
		close S;
		my $color=$#html > -1 ? $COLOR_KO : $COLOR_OK;
		my $txt=$#html > -1 ? "Alter " : "No critial event";
		push @res,"<div>\&$color $txt</div>";
		push @res,@html;	
		push @out_html,@res;

	}
	
	$cmd1="ssh $name lssystemstats -nohdr -delim :";
	print "$cmd1 \n";
	if(open STAT,"$cmd1 |"){
		my %stats;
		while(my $l=<STAT>){
			my @stat=split/:/,$l;
			$stats{$stat[0]}=$stat[2];
		}
		close STAT;
		my @data;
		push @data,"\n\n[storwize.rrd]";
		foreach my $k(keys %stats){
			push @data,"DS:$k:GAUGE:300:0:U $stats{$k}";
		}
		my $DATA=join "\n",@data;
		my $cmd="$BB $XYMONDISP \"data $name\.trends $DATA\" ";
		print "Data Send : $cmd\n";
		system("$cmd");
	}



	push @out_html,"<br><br><hr>ibm-storwize.pl <a href=\"mailto:pierrejacques.mimifir\@shanaconsulting.org\">Version $VERSION (c) 2018  Pierre-Jacques MIMIFIR</a></br></br>";
	$MSG=join " ",@out_html;
	my $status="status $name.$COLUMN $COLOR\n\n\n";
	my $date=`date`;
	my $cmd="$BB $XYMONDISP \"$status $date $MSG\"";
	#print "$cmd\n";
	system("$cmd");
	
	@out_html=();
	
}
