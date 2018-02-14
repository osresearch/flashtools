Read and write system firmware
===

This is a very simplified version of the flashrom utility designed
for reading and writing SPI flash chips attached to the CPU.
Access is controlled through the PCH and SMM, so this will only
work if the various control bits are turned off.

*Do not use this unless you have a way to recover!*

Using this tool can "brick" your machine by making it unable to come out
of reset.  Recovering from a bad firmware flash typically requires
physical access to the SPI flash chip and an external programming
device. 
