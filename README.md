Sn0ffer
=======

Sn0ffer - Make sound/noise/music with your network connection!

.Introduction:
I'm a sec-admin in a 3,000 users company. My SIEM harvesting many syslog for forensic analysis but i like to see what happens, on some network interfaces, in real time. But like many sec-admins, i don't have many time to spend watching syslogs flow.
As many computer engineer, i'm often listening music when i'm working, which allows me to be more concentrated on what i'm working at.
So, one day i thought: why not transform this flow of syslogs into sound to listen? Like this I can spend my time to work like every day and listen to what is happening on my network.
Uh, could be nice, but i'm not a real coder and this sound like a very big development project. Erf!
Anyway, let's try to do something!

.About:
The first public release, v0.5.1, of Snoffer (sniffer-sound-offer) just listening the network connection of a local client with some Perl scripts sniffers.
These Perl sniffers transform the destination port (for TCP and UDP packets), or Ethernet type (for layer 2 frame), into data and send it to a local listening socket used by a PureData patch (netreceive function) which is used to generate 'audible' frequences.
The second public release, v0.5.4, offer you to choose the listening interface (-i switch) and some other stuff like recording your 'capture'.

.Be clear, be short:
Video demo of Sn0ffer v0.2: 	http://player.vimeo.com/video/37365477
Capture of Sn0ffer v0.5:	http://soundcloud.com/t4d/record-snoffer-v0-5-home
Live set with Sn0ffer inside:	http://vimeo.com/41089881 (on the right, around 07:20)

.Using it:
You have to install PureData-extended version (http://puredata.info/downloads/pd-extended).
You need to install Perl on your local machine, and some of necessary libraries, as Net::PcapUtils, NetPacket::Ethernet, NetPacket::IP, NetPacket::UDP, NetPacket::TCP, IO::Socket::INET, and maybe some others (as pcap libs).

Start the PD patch,
Start Perl scripts as root/superuser,
Enjoy!
--

http://snoffer.tad0.org
