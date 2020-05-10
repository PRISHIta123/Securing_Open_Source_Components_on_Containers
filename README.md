# Securing_Open_Source_Components_on_Containers
Code for HPE Project 

Team Members:
1. Prishita Ray- 17BCE2405
2. Tanmayi Nandan- 17BCI0039
3. V Bhavyashri Vedula- 17BCI0115
4. Saripella Vivekananda Verma- 17BCI0104

Steps to install Docker on Linux Ubuntu 18.04 is available at the following link:
https://www.digitalocean.com/community/tutorials/how-to-install-and-use-docker-on-ubuntu-18-04

Tools that we can use for scanning: Anchore, Clair, Dadga, OpenSCAP, Sysdig Falco
https://opensource.com/article/18/8/tools-container-security 

## Vulnerabilities reported by Anchore-Engine using CLI

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