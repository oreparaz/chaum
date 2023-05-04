# to build:
# docker build -t <name> .
# to run:
# docker run --rm -it <name>
FROM python:2.7
ADD . /work
WORKDIR /work
CMD ["/bin/bash"]
