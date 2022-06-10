Mail Exploitation:

=================

Basics:

	E-Mail Basics:		Terms:

			ESP:(Email Service Providers)

				Example:

					Gmail

					Yahoomail

			Spam:

				Doubt:

					Difference in spam and junk

		E-Mail Address:

			Basics:

			Syntax:

				user@system

		E-Mail Headers:

			Normal Headers:

				1. From:

					This header displays email address & optionally the name of sender, however, this can be easily forged and thus is not reallyx reliable.

				2. To:

					This header contains email address and optionally the name of primary recepient.

				3. CC:(Carbon Copy)

					This header contains list of email addresses of other recipients to whom the message is sent.

				4. BCC:(Blind Carbon Copy)

					This header is same as CC header, however, the difference between them is that email addresses of recipients listed in the BCC are not shown to the recipients of the message other than primary recepient.

				5. Date:

					This shows the date and time the email message was composed.

				6. Delivery Date:

					This shows the date and time at which the email was received by your (mt) service or email client.

				7. Subject:

					This is what the sender placed as a topic of the email content.

				8. Message-ID:

					This header is a unique string assigned by the email client when the message is first created. These can be easily forged.

				9. User-Agent:

					This header contains the email client that was used by the sender of the message.

				10. In-Reply-To:

					This is an optional header is only present if the email is a reply yo another email. Value of this header is Message-ID of the email to which the mail is a reply.

				11. References:

					This is an optional header which is is same as "In-Reply-To" header, however it contains Message-ID of every email in an email-thread as its value.

				12. Return-Path:

					This header contains email address to which email is sent if an error is encountered while sending the email to the intended inbox. In most cases, this header contains email address of sender(ie, 'the user' in this case).

				13. Reply-To:

					This is an optional header which is present only when the reply to an email is sent to an email address which is different from sender's email address.

				14. Mailed-By:

				15. Envelope-To:

				16. Signed-By:

				17. Received:(Most Important Email Header)

					This header contains a list of all the servers/computers through which the message traveled in order to reach the reciever.

					This header typically identifies the machine that received the mail and the machine from which the mail was received. So every time an email passes through a SMTP server, it inserts a Received header in itself. So usually, an email contains more than one Received header.

					First "Received:" header is of reciever's own system or mail server.

					Last "Received:" header is from where the mail originated.

					Note:

						Received headers are best read from bottom to top, ie, read the bottom-most Received header and then go towards the top.

					Note:

						Received is the most important header as every other header except Received can be forged.

				18. Mime-Version:

					This header specifies MIME version.

				19. Content-Type:

					This header indicates message format, ie, either HTML or PlanText.

				20. Message Body:

					This header contains the message written by the sender.

			Security Headers:

				1. Security:

				2. Authentication-Results:

				3. Received-SPF:

					Read SPF Section below.

				4. DKIM-Signature:

					Read DKIM Section below.

				5. Domainkey-Signature:

					Read DKIM Section below.

				6. ARC-Seal:

					Read ARC Section below.

				7. ARC-Message-Signature:

					Read ARC Section below.

				8. ARC-Authentication-Results:

					Read ARC Section below.

			X-Headers:

				Basics:

					Headers whose name begin with "X" are headers created by the recipient's email server and are considered to be trustworthy.

				Headers:

					1. X-Originating-IP:(Important Header)

						This header is important since it tells you the IP address of the computer that had sent the email.

						Note:

							If "X-Originating-IP" header is absent, then look into the "Received" headers to find the sender's IP address.

						Note:

							Once the email sender's IP address is found, you can search for it at http://www.arin.net/ to get which ISP or webhost the IP address belongs.

							If you are tracking a spam email, you can send a complaint to the owner of the originating IP address, ie, ISP or the webhost. Be sure to include all the headers of the email when filing a complaint.

					2. X-Received:

					3. X-Distribution:

					4. X-Mailer:

					5. X-UIDL:

					6. X-Spam-Score:

					7. X-Spam-Flag:

					8. X-Spam-Status:

						This header displays a spam score created by recipient’s email client. Based on the score, Email is marked is spam or not-spam & this score also decides the value of "X-Spam-Level" header.

					9. X-Spam-Level:

						This header depends on value of "X-Spam-Status" header. Value of this header is in asterisks & number of asterisks is same as value of "X-Spam-Status" header's value.

		E-Mail Attachment:

			Basics:

			Formats:

				MIME:(Multipurpose Internet Mail Extensions)

					Basics:

	E-Mail Protocols:

		Basics:

			E-Mail Server:

				OutBound Server:

					Basics:

				InBound Sever:

					Basics:

				MX Server:(aka Mail Exchanger)

					Basics:

				MailBox:

					Basics:

						Mailbox is a destination to which email messages are delivered.

				Inbox:

				Outbox:

			Agents:(Mailing Software)

				SMTP/POP3/IMAP4 Agents:(Common Agents)

					MUA:(Message/Mail User Agent)(aka Email Client)(aka Client)

						Basics:

							MUA refers to a website/software/app which is used to send & manage emails of the client(user).

						Types:

							A. Software-Based MUA:

								Basics:

								Common Software:

									Thunderbird:

									EXIM:

							B. Webmail:(Web Email)

								Basics:

				SMTP Agents:

					MTA:(Message/Mail Transfer Agent)(aka Mail Relay/Server)

						Basics:

							Its a software installed on SMTP server & is basically responsible for receiveing mails from MUA(or MSA) & forwarding them to another MTA or MDA.

						Types:

							A. Software-Based MTA:

								Common MTA:

									Linux:

										SendMail:

											SendMail is first MTA ever made for SMTP. Its still in use!

										Postfix:

										Dovecot:

											Basics:

												Dovecot is a IMAP & POP3 sever for *nix OS.

										Exim:

									Windows:

							B. Webmail Server:

								Basics:

									A webapp that provides message management, composition & reception functions is called a webmail.

						Note:

							MTA is also called SMTP server or MTA server sometimes, but they are not actually same as MTA is software that is installed on SMTP server.

							Note:

								Read Understanding SMTP Section to read about SMTP Server.

				ESMTP-only Agents:

					MSA:(Message/Mail Submission Agent)

						Basics:

							MSA is a software used to recieve emails from MUA and to cooperate with MTA for delivery of mail using ESMTP.

							MSA is used to manage the rewriting of orignal messages to fix formatting issues when sending messages outside the organization.

				IMAP4/POP3 Agents:

					MDA:(Message/Mail Delivery Agent)(aka LDA(Local Delivery Agent))

						Basics:

							MDA is a software responsible for delivery of emails to local recipient's mailbox.

		Protocols:

			To Send Emails:

				SMTP(25/465/587/1025/2525):(Simple Mail Transfer Protocol)

					Understanding SMTP:

						Protocols:

							SMTP:(Orignal SMTP Protocol)(Simple Mail Transfer Protocol)

								Basics:

									SMTP is an internet standard communication protocol developed in 1982 & is used for email communication.

									SMTP is used by MTA & email servers to send & recieve emails.

								Commands:

									Read SMTP Commands Section.

							ESMTP:(Extended Simple Mail Transfer Protocol)(Mordern SMTP)

								Basics:

									As internet and digital business bloomed, SMTP usage became more widespread and commercial, that resulted in spam. To fix it, ESMTP was created in 1995.

									Versions:

										Lastest Version => 2008

								Commands:

									Read SMTP Commands Section.

						Ports:

							For SMTP Relay:

								Port 25:(Default port)

									Because of spammers using port 25 to send spam mails, many ISPs ending up blocking port 25, so now-a-days, port 25 is used for SMTP Relaying

							For SMTP Email Submission:

								Port 465:(SMTPS(SMTP over SSL))

									Although its deprecated now, many services still use it

								Port 587:(SMTP over TLS)

									Its used for Email Submission

								Port 1025:

									Its used when neither port 587 nor port 2525 are availablw

								Port 2525:

									Its used as an alternative to port 587

						SMTP Commands & Codes:

							Basics:

							Commands:

								SMTP:

								1. HELO:(SMTP)

									Basics:

										Its used to initiate/start SMTP session. 

									Syntax:

										HELO domain/ip

								2. EHLO:(ESMTP)

									Basics:

										Its used to initiate/start ESMTP session. Its basically used to see whether a server supports ESMTP.

									Syntax:

										EHLO domain/ip => If it shows error, then the server dont support ESMTP.

								3. MAIL FROM:

									Basics:

										It initiates a mail transfer.

									Syntax:

										MAIL FROM "user@site.com"

								4. RCPT TO:

									Basics:

										Its used to specify the recipient.

									Syntax:

										RCPT TO "user@site.com"

								5. DATA:

									Basics:

										Its used by client to ask server for permission to transfer mail data.

									Syntax:

										DATA //said by client(us)

										354 //said by server (response code)

										<mail data>

											'.' is used to terminate mail data transfer.

								6. NOOP:

									Basics:

										Its used to check if server can respond.

									Syntax:

										NOOP

								7. EXPN:

									Basics:

									Syntax:

								8. VRFY:

									Basics:

										Its used to verify whether a particular user has a mailbox.

									Syntax:

										VRFY <username>

								9. RSET:

									Basics:

										Its used to the reset the connection to the initial state.

									Syntax:

										RSET

								10. QUIT:

									Basics:

										Its used to terminate the SMTP session.

									Syntax:

										QUIT

								11. STARTTLS:

									Basics:

										Its used to start a TLS handshake for a secure SMTP session. It also resets the SMTP sesssion to the initial state.

									Syntax:

										STARTTLS

								12. AUTH:

									Basics:

										Its used to authenticate the client to server.

										Auth/Login Methods:(3)

											A. PLAIN:

												Here, server requests the client to authorize using the username and password together in base64 format.

											B. LOGIN:

												Here, server requests the client to authorize using the username and password separately in base64 format.

											C. GSSAPI:(Generic Security Services Application Program Interface)

												Types:(2)

													1. Plain:

													2. NTLM:

											D. DIGEST-MD5:

											E. MD5:

											F. CRAM-MD5:

											G. OAUTH10A:(OAuth 1.0a)

											H. OAUTHBEARER:(OAuth 2.0)

											I. XOAUTH2:(or XOAUTH)

												Here, server requests OAuth 1.0 or OAuth 2.0 access token in Base64 format.

									Syntax:

										AUTH <Login_Method>

									Note:

										SMTP AUTH only works on port 25 & 587.

								13. ATRN:

									Basics:

										Its an alternative for TURN command(now obselete). Its used to reverse the connection between sender & reciever

									Syntax:

										ATRN sender_ip_or_domain,reciever_ip_or_domain

								14. BDAT:

									Basics:

										Its used an alternative for DATA command & is used to sumbit mail contents. However, there is no need of using '.' to terminate the message.

									Syntax:

										BDAT <length> LAST

										<Contents>

								15. ETRN:

									Basics:

										Its used to start SMTP queue processing of a specified server host.

									Syntax:

										ETRN domain_or_ip_address

							Response Codes:

								354:

									Its used to grant permission to client to transfer mail data.

						SMTP Server:(aka Relay Server)

							Basics:

								It refers to a computer or a software responsible for sending emails following SMTP.

								SMTP server receives emails from MUA, Then it relay those emails to another SMTP server or the incoming mail server(IMAP4 or POP3 server).

							SMTP Server Address:

								Type:

									Web Address:

										smtp.domain.xyz

										mail.domain.xyz

									Local Address:

										IPv4

							SMTP Relaying:

								SMTP Relay is a process of transferring emails between SMTP Servers on the way to the recipient’s server

								Note:

									Relaying means "to receive & pass on".

							SMTP Queue:(aka Email Queue)

								It is a system that creates an array of emails that are waiting to be processed for delivery

						SMTP Record:(aka DNS MX Record)

							Basics:

								MX Record directs emails to SMTP server.

							Structure:

								Parts:

									Basics:

									Syntax:

								Example:

							Backup MX Record:

						SMTP Conversation:(3 Steps)

							Step-1: SMTP Handshake:(Establish TCP Connection)

								Process in which MUA connects to SMTP server via SMTP port in order to establish the connection between the sender & the SMTP Server is called SMTP Handshake.

							Step-2: Email Transfer:

								Step-2a: SMTP Session begins:

									Once the connection is established between sender & the SMTP server, the SMTP session begins.

									Once the session begins, MUA submits the sender’s and recipient’s email addresses, as well as the email body and attachments, to the SMTP server.

								Step-2b:

									MTA checks whether the domain name of the recipient and the sender are same:

										A. If domain names are same:

											SMTP server sends the email directly to the recipient’s POP3 or IMAP4 server.

										B. If domain names are different:

											Step-1:

												Sender's SMTP server requests DNS to get MX records to retrieve recipient's IP address.

											Step-2:

												Sender’s SMTP server connects to recipient’s SMTP server using recipient's IP and then relays the email via SMTP Relaying.

											Step-3:

												Recipient’s SMTP server verifies the incoming email. If the domain and user name has been recognized, the server forwards the email to the POP3 or IMAP4 server.

									Note:

										If the recipient’s server is not available (down or busy), the email will be put into an SMTP queue.

							Step-3: Termination:(Close TCP Connection)

							Note:

								Very commonly, terms "MTA" & "SMTP Server" are used interchangeably, but they are not same.

								MTA is just a software that is installed on SMTP Server.

								Note:

									Read Agents Section to read about MTA.

					Enumeration:

						Connecting to SMTP server:

							1. Using Netcat:

								nc -nv ip 25

							2. Using Telent:

								telnet ip 25

								Meta-Commands:

									VRFY email_id/username:

										Its used to verify an email address

										If output code is: 

											250/251/252=>user account is valid

											550=>invalid user account.

									EXPN:

										Its used to ask server for the membership of a mailing list.

						User enumeration:

							A. VRFY Command:

								Explained in above section.

							B. Smtp-User-Enum:

								Basics:

								Usage:

									smtp-user-enum -M <mode> -u <user_name> -t <ip>

									Flags:

										-M => mode(EXPN | VRFY | RCPT)

										-u => username list

										-t => host/ip

						Enumerating MailBox:

							Thunderbird:(GUI)

			To Recieve Emails:

				POP3(110/995):(Post Office Protocol Version 3)

					Understanding POP3:

						POP3 Protocol:

							Basics:

								POP3 is an application layer(layer3) TCP/IP protocol used by an user as an email-client to retrieve user's mailbox from the mail server.

								As compared to IMAP4, POP3 is a simpler way to access mail

								Versions:

									POP1 => 1984

									POP2 => 1985

									POP3 => 1988 => Current Version

									POP4 => 2004 but development is paused.

						POP3 Ports:

							110 => POP3

							995 => POP3S(POP3 over SSL/TLS)

						POP3 Server:

							Basics:

					Enumeration:

						Connecting to POP3 server:

							Telnet:(Binary)

								telnet <ip> 110:

									user "user"@ip

									pass "password"

									Meta-Commands:	

										list => list all emails

										retr x => retrive mail no. x

										quit => exit

							Thunderbird:(GUI)

				IMAP4(143/993):(Internet Message Access Protocol Version 4`)

					Understanding IMAP:

						IMAP Protocol:

							Basics:

								IMAP is a communication protocol used to access emails stored on SMTP server.

								Versions:

									IMAP4

						IMAP Ports:

							143 => IMAP

							993 => IMAPS(IMAP over SSL)

						IMAP Commands & Codes:

						IMAP Server:

							Basics:

					Enumeration:

						Connecting to IMAP4 server:

							Thunderbird:(GUI)

						Enumerating MailBox:

							Thunderbird:(GUI)

			Uncategorized:

				MAPI:(Messaging Application Programming Interface)

					Read Windows Internals Sheet.

				Email API:(aka Web API)(aka HTTP API)

					Basics:

						Email API is just a name to refer to using HTTP protocol for sending emails.

						It can be think of as an alternative to SMTP Server.

E-Mail Security & Bypass:

	Message Encryption Protocols:

		Basics:

			Mechanisms/protocols to encrypt the message & attachments.

		Mechanisms:

			SSL/TLS:

			S/MIME:(Secure/Multipurpose Internet Mail Extensions)

				Basics:

			PGP:(Pretty Good Privacy)

				Read Password Cracking & Cryptography Sheet.

			Bitmessage:

	E-Mail Authentication Protocols:(aka Authentication Mechanisms)(aka Authentication Systems)

		Basics:

			Email authentication is process of using multiple methods/mechanisms/protocols/systems/frameworks to ensure that E-Mails/messages are not faked/forged/Tampered before they get delivered.

			Reciever Servers (Mail servers on the receiving end) use these protocols to verify sender's identity and to check that emails weren’t altered in transit, and they inform reciever servers what to do with messages that aren’t authenticated.

			Usuallt unauthenticated e-mails are sent into SPAM section.

		In-Built Authentication Mechanisms:(1)

			SMTP Auth:

				Read SMTP AUTH Sub-Section above.

		Additional Mechanisms:(4)

			A. SPF, DKIM & DMARC:

				Note:

					I have put these three in a seperate category as they are quite similar.

				Mechanisms:

					1. SPF:(Sender Policy Framework)

						Basics:

							SPF orignated as an anti-spam mechanism. However, now its used as an anti-phishing mechanism.

							SPF is compatible with DKIM.

						SPF Working:

							Overview:

								Let's say, i have a domain xyz.com with IPv4 address 'a.b.c.d' & this domain allows to send emails. Some attacker spoofed his email id to '1234@xyz.com' by just changing an email header and due to lack of SPF, he succeded in doing damage to victim.

								So, i created a SPF DNS record and according to it, any email sent from any IP address other than 'a.b.c.d' is unauthenticated. So when a person(victim) recieves email from email address '1234@xyz.com', victim's email client queries DNS server of xyx.com for it's SPF record, and compares the IP address mentioned in SPF record with the IP address of attacker. If these two IP addresses do not match, then, the email client moves the mail to spam.

							SPF Record:(aka SPF DNS Record)(aka SPF DNS TXT Record)

								Basics:

									SPF Record is a special type of TXT DNS Record which is used to prevent Email Spoofing.

									Note:

										A domain can have only one SPF Record.

								Structure:

									Basics:

										SPF records consists of 3 parts.

									Parts:(4)

										A. SPF Mechanisms:

											Basics:

												A mechanism is a way to specify a range of IP addresses.

											Types:(8)

												1. ALL:

													Basics:

													Syntax:

												2. A:

													Basics:

														It specifies domain name allowed to send emails for the domain

													Syntax:

														a=<domain>

												3. MX:

													Basics:

													Syntax:

												4. PTR:

													Basics:

													Syntax:

												5. exists:

													Basics:

													Syntax:

												6. INCLUDE:

													Basics:

														Its used to authorize 3rd party domains/organizations to send emails on behalf of the domain.

													Syntax:

														include:<domain_name>

												7. IP4:

													Basics:

														It specifies IPv4 address/range allowed to send emails for the domain

													Syntax:

														ip4=<IPv4>

												8. IP6:

													Basics:

														It specifies IPv6 address/range allowed to send emails for the domain

													Syntax:

														ip6=<IPv6>

										B. SPF Qualifiers:

											Basics:

												A qualifier can be used with any spf mechanism to specify the result of mechanism's evaluation.

											Types:(4)

												1. +:(Default)

													Its used to allow if SPF mechanism evaluation is true.

												2. -:

													Its used to do nothing irrespective of result of SPF mechanism evaluation.

												3. ~:

												4. ?:

													Its used to allow if SPF mechanism evaluation is flase.

										C. SPF Modifiers:

											Basics:

											Types:(2)

												1. EXP:

													Basics:

													Syntax:

												2. REDIRECT:

													Basics:

														Note:

															Redirect Modifier is different from Include Mechanism as:

													Syntax:

										D. Others:

											1. V:

												Basics:

													It specifies SPF version

												Syntax:

													v=<spf_version>

											2. ALL:

												Basics:

													It tells the server what to do with emails that are not authorized.

												Syntax:

													-all => Reject all such emails

													~all => Send all such emails to spam

													+all => Send all emails to inbox irrespective of its source

									Note:

										It's mandatory to either end SPF record with 'all' or include a 'redirect' in the record.

								Example:

									v=spf1 +a +mx +ip4:194.123.23.0/24 +ip4:149.23.126.0/21 +ip4:92.8.4.23 –all

						SPF Enumeration:

							Basics:

								SPF Enumeration basically means reading the SPF record.

							Using Dig:

								dig TXT domain.com

								Note:

									Read Active Information Gathering Sheet to read more about Dig.

					2. DKIM:(DomainKeys Identified Mail)(aka DKIM Authentication)

						Origin of DKIM:

							DK:(DomainKeys)(aka Yahoo's DomainKeys)

								DomainKeys is a deprecated e-mail authentication system developed by Yahoo in 2007 to verify email sender's domain name & integrity of message.

							IIM:(Identified Internet Mail)

								IIM was developed by Cisco

						Basics:

							DKIM was created in 2013 by Yahoo by merging IIM & DomainKeys.

							DKIM is used to verify the authenticity of email, in order to detect & prevent email forgery/tampering/spam by adding Digital Signature Header in email headers.

							DKIM is compatible with SPF & DMARC.

							Why do we need DKIM:

								Normally, there is "From" Header to identify the sender of an email, however, it can be edited & thus is not reliable. So, DKIM signature header acts as the identifier.

							DKIM Advantages:

								1. ISPs build domain reputation over time based on DKIM.

								2. SPAM Reduction

							Note:

								"DKIM is not same as TLS/SSL" as DKIM do not encrypt the email, so any person can easily the emails in absence of TLS/SSL. DKIM is only responsible for verifying the authenticity of the email.

						DKIM Working:

							Overview:

								Step-1:

									Sender sever sends these two things:

										A. Message signed with 'DKIM Signature' using 'Signing Algorithm'. This hash is stored inside 'DKIM-Signature' Header.

										B. Orignal Message

								Step-2:

									Reciever queries Sender's DNS server for DKIM Record to get Public key.

								Step-3:

									Reciever uses Sender's public key to decrypt the 'DKIM-Signature' header's value.

									If decrypted value is same as 'Orignal Message', DKIM allows the message as its valid. Otherwise, it sends the mail to SPAM.

							DKIM Structure:(2)

								A. DKIM-Signature:(DKIM Signature Header)

									Basics:

										"DKIM-Signature" is header name for DKIM email header.

									Structure:

										1. V:

											Basics:

												DKIM version

											Sytax:

												v=dkim_version;

										2. A:

											Basics:

												Signing Algorithm

												Algorithms allowed:(2)

													A. rsa-sha1

													B. rsa-sha256

											Syntax:

												a=dkim_algo;

										3. S:

											Basics:

												It defines the DKIM Selector, ie, name of DKIM key to get from the DKIM record.

												Note:

													Read DKIM Record sub-section below to read about "Selector".

											Syntax:

												s=value;

										4. D:

											Basics:

												Name of domain that has signed the message.

											Syntax:

												d=domain_name;

										5. I:

											Basics:

												Email-id of Signer.

											Syntax:

												i=signer_id;

										6. H:

											Basics:

												List of signed header fields.

											Syntax:

												h=header1:header2;

										7. BH:(Body Hash)

											Basics:

												Value of hash of message.

											Syntax:

												bh=body_hash;

										8. B:

											Basics:

												Value of digital sign

											Syntax:

										9. Q:(Optional)

											Basics:

												Default query method

											Syntax:

										10. C:(Optional)

											Basics:

												It sets the 'Canonicalization posture' for header and body.

												Values:(2)

													A. Relaxed:

														Simple changes are allowed to whitespace and header line-wrapping.

													B. Simple:

														No changes allowed.

											Syntax:

												c=header_canonicalization_posture_value/body_canonicalization_posture_value;

										11. L:(Optional)

											Basics:

												Length of the canonicalized part of the body that has been signed.

											Syntax:

										12. T:(Optional)

											Basics:

												Signature timestamp

											Syntax:

										13. X:(Optional)

											Basics:

												Expire time

											Syntax:

									Example:

										DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=sparkpost.com; s=google; h=from:content-transfer-encoding:subject:message-id:date:to:mime-version; bh=ZkwViLQ8B7I9vFIen3+/FXErUuKv33PmCuZAwpemGco=; b=kF31DkXsbP5bMGzOwivNE4fmMKX5W2/Yq0YqXD4Og1fPT6ViqB35uLxLGGhHv2lqXBWwFhODPVPauUXxRYEpMsuisdU5TgYmbwSJYYrFLFj5ZWTZ7VGgg6/nI1hoPWbzDaL9qh

								B. DKIM Record:(aka DKIM DNS Record)(aka DKIM DNS TXT Record)

									Basics:

										A DKIM Record contains one or more Public Keys as a DNS TXT Record.

										In case of multiple keys, a special value "Selector" is used to identify the key.

									Naming Syntax:

										<selector_name>._domainkey.<domain_name.com>

									Structure:

										Parts:(2)

											1. V:

												Same as DKIM-Signature

											2. P:

												Basics:

												Syntax:

										Example:

											v=DKIM1; p=76E629F05F709EF665853333EEC3F5ADE69A2362BECE40658267AB2FC3CB6CBE

									Example:

						DKIM Enumeration:

							Basics:

								DKIM enumeration basically means reading the DKIM record.

							Using Dig:

								dig <selector_name>._domainkey.<domain_name.com> TXT

					3. DMARC:(Domain-based Message Authentication, Reporting, and Conformance)

						Basics:

							DMARC is an email authentication policy system built on SPF & DKIM.

							It basically tells the reciever's sever what to do in case both SPF & DKIM fail to verify/authenticate a mail, it also produces a weekly XML report to show the actions DMARC took.

						DMARC Working:

							DMARC Record:(aka DMARC DNS Record)(aka DMARC DNS TXT Record)

								Basics:

									A DMARC Record is a DNS TXT Record consisting of one or more DMARC Policies.

								DMARC Policy:

									Basics:

										DMARC policy determines what happens to an email after it is checked against SPF and DKIM records.

										DMARC policy determines if failure results in the email being marked as spam, email getting blocked, or email being delivered to its intended recipient.

										Types:(3)

											A. None:

											B. Quranatine:

											C. Reject:

									Structure:

										Parts:

											1. V:

												Basics:

													DMARC Version

												Syntax:

													v=<dmarc_version>;

											2. P:

												Basics:

													DMARC Policy

												Syntax:

													p=<policy_name>;

											3. RUA:(Optional)

												Basics:

													Email-Id to send DMARC report to.

												Syntax:

													rua=<email_id>;

											4. ADKIM:(Optional)

												Basics:

													Sets DKIM Checks to Strict or Relaxed.

													Check Types:(2)

														A. Strict:

														B. Relaxed:

												Syntax:

													adkim=<value>;

													Values:(2)

														A. s => Strict

														B. r => Relaxed

											5. ASPF:(Optional)

												Same as ADKIM but for SPF.

										Example:

											v=DMARC1; p=quarantine; adkim=r; aspf=r; rua=mailto:example@third-party-example.com;

												This means if DKIM & SPF checks fail, qurantine the mail and 

							DMARC Report:(DMARC Weekly XML Report)

								Basics:

						DMARC Enumeration:

							Basics:

								DMARC Enumeration basically means reading the DMARC record.

							Using Dig:

								dig _dmarc.<domain.com> TXT

				Bypass Stratergy:

					Steo-1:

						Check if SPF/DKIM/DMARC even exist by trying to enumerate DKIM/SPF/DMARC DNS Records.

					Step-2a:If SPF/DKIM/DMARC exist

			B. BIMI:(Brand Indicators for Message Identification)

				Basics:

					BIMI is the latest email authentication protocol.

			C. Accepted Domains:

				Read MS Exchange Server Exploitation Sheet.

			D. ARC:(Authenticated Received Chain)

				Basics:

					ARC is an email authentication system designed to allow an intermediate mail server to sign an email's original authentication results.

					This allows a receiving service to validate an email when the email's SPF and DKIM records are rendered invalid by an intermediate server's processing

SRS:(Sender Rewriting Scheme)

E-Mail Analysis:(E-Mail Forensics)

	Finding Sender's IP:

		Read "X-Originating-IP" Sub-Section in Email Headers Section.

	Read:

		https://www.socinvestigation.com/email-header-analysis-use-cases-including-spf-dkim-dmarc/

E-Mail Attacks:

	E-Mail Spoofing:(aka E-Mail Forgery)

		Email spoofing is the forgery of an email header so that the message appears to have originated from someone or somewhere other than the actual source.

		Uses:

			Email Phishing

			Spreading Malware

			Gaining sensitive info like credit card details

	E-Mail Tampering:

		E-Mail Tampering refers to changing message contents of an email.

	E-Mail Phishing:(E-Mail Fraud)

		When E-mail Spoofing is used to gain victim's credentials, its called E-mail Phishing. E-Mail Phishing is most used type of phishing.

	E-Mail MITM:

	Malicious Attachment:

		Bypass ESP:

Doubts:

	What is MX record and what is its relevance with respect to email server?
