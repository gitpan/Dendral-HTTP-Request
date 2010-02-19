use 5.008001;
use strict;
use ExtUtils::MakeMaker;

my @IncludeDirs = ($ENV{'APACHE_INCLUDE'},
                   "/usr/local/include/apache",
                   "/usr/include/apache",
                   "/usr/include/apache13",
		   "/usr/include/apache-1.3",
                   "/usr/include/apache2",
                   "/opt/include/apache",
                   "/usr/local/apache/include");

my @APRIncludeDirs = ($ENV{'APR_INCLUDE'},
                      "/usr/local/include/apr-1",
                      "/usr/include/apr-1");

sub NeedToInstallApache
{
	my $Error = shift;
	warn $Error .
	"\nYou should install Apache 1.3.X or Apache 2.X first!\n" .
	"Sources of Apache available here: http://https.apache.org/\n".
	"You may also define the APACHE_INCLUDE environment variable.";
	exit;
}

sub SearchDir
{
	my $File = shift;
	foreach (@_)
	{
		return $_ if (-e "$_/$File");
	}
return undef;
}

print "perl thinks the current OS is '$^O'\n";


my $CC  = 'cc';

my $ApacheIncludeDir = SearchDir('httpd.h', @IncludeDirs);
unless ($ApacheIncludeDir) { NeedToInstallApache("Cannot find header file httpd.h"); exit; }

my $APRIncludeDir = '.';
if ($ApacheIncludeDir =~/apache2/)
{
	$APRIncludeDir = SearchDir('apr.h', @APRIncludeDirs);
}

WriteMakefile(
	'NAME'          => 'Dendral::HTTP::Request',
	'VERSION_FROM'  => 'lib/Dendral/HTTP/Request.pm',
	'DEFINE'        => '-O2 -g ',
	'INC'           => "-I$ApacheIncludeDir -I/usr/include -I/usr/local/include -I. -I$APRIncludeDir ",
	'CC'            => $CC,
	'LD'            => $CC,

	'C'             => ['Request.c', 'RequestParser.c', 'DefaultParser.c', 'MultipartParser.c', 'UrlencodedParser.c'],
	'XS'            => {'Request.xs' => 'Request.c'},
	'OBJECT'        => '$(O_FILES)',

	'TYPEMAPS'      => ['perlobject.map'],
	'AUTHOR'        => 'Andrei V. Shetuhin <reki@reki.ru>'
);
