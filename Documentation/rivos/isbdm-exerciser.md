ISBDM exerciser
===============

2 Feb 2023 mev


# Goal

The ISBDM exerciser driver aims to:

   - Discover and attach to all ISBDM instances
   - Export a char device
   - Allow userspace to:
    - View link status
    - Register receive buffers for remote messages, and transmit to
      remote
    - Register memory regions
	- Issue RDMA and AMO commands to the remote side
   - Deal with command completion IRQs, and incoming RX message
     notifications

# Interface

## Link status

## Message buffers

## Registered Memory Buffer Array

PASID, User/Supervisor, RO/RW

Registering a userspace range is fine (modulo SVA complexity), but
what about supervisor?  Could special-case that.  (Or hope DV does it,
unless we explicitly need it.)


# Interrupts

Send command: completion
