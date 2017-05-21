Drop is an inter-project dependencies tool that binds functionality of
source control systems, autoconf scripts, make and package managers.

There are a lot of tools orchestration and deployment to production
but very few tools to help someone configure a machine for development.
dws is just a tool.

At its core, dws helps to run multiple sequences of _dev_ commands in
topological order. ex:

    git clone _repo-1_
    ./configure
    make
    make install
    git clone _repo-2_
    ./configure
    make
    make install

is replaced by a single command:

    dws build _myproject-and-prerequisites_.xml
