# zswap6to3
This repository is to migrate zswap from linux6.4.3 to linux3.12.60  


This repository is based on linux3.12.60, with several files changed:
- zswap.c: Original zswap.c was deleted, current zswap.c is in fact from Linux6.4.3
- myInterface.c: the interface file for migration
- myInterface.h: the interface file for migration