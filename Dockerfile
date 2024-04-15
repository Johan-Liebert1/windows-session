FROM debian:latest

RUN apt-get update && apt-get install -y \
   sudo gpg curl rlwrap

RUN echo 'deb http://download.opensuse.org/repositories/home:/uibmz:/opsi:/4.2:/stable/Debian_11/ /' | sudo tee /etc/apt/sources.list.d/home:uibmz:opsi:4.2:stable.list
RUN curl -fsSL https://download.opensuse.org/repositories/home:uibmz:opsi:4.2:stable/Debian_11/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/home_uibmz_opsi_4.2_stable.gpg > /dev/null
RUN sudo apt update
RUN sudo apt install winexe -y

# Spawn a shell
CMD ["/bin/bash"]
