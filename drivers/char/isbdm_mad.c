// SPDX-License-Identifier: GPL-2.0

/* Authors: Evan Green <evan@rivosinc.com> */
/* Copyright (c) 2023 Rivos Inc. */

#include <linux/pci.h>
#include <linux/types.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_smi.h>

#include "isbdmex.h"
#include "isbdm_verbs.h"
//#include "isbdm_mem.h"

#define IB_SMP_UNSUP_VERSION \
	cpu_to_be16(IB_MGMT_MAD_STATUS_BAD_VERSION)

#define IB_SMP_UNSUP_METHOD \
	cpu_to_be16(IB_MGMT_MAD_STATUS_UNSUPPORTED_METHOD)

#define IB_SMP_UNSUP_METH_ATTR \
	cpu_to_be16(IB_MGMT_MAD_STATUS_UNSUPPORTED_METHOD_ATTRIB)

#define IB_SMP_INVALID_FIELD \
	cpu_to_be16(IB_MGMT_MAD_STATUS_INVALID_ATTRIB_VALUE)

static int reply(struct ib_smp *smp)
{
	/*
	 * The verbs framework will handle the directed/LID route packet
	 * changes.
	 */
	smp->method = IB_MGMT_METHOD_GET_RESP;
	if (smp->mgmt_class == IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE)
		smp->status |= IB_SMP_DIRECTION;

	return IB_MAD_RESULT_SUCCESS | IB_MAD_RESULT_REPLY;
}

static int subn_get_nodedescription(struct ib_smp *smp,
				    struct ib_device *ibdev)
{
	if (smp->attr_mod)
		smp->status |= IB_SMP_INVALID_FIELD;

	memcpy(smp->data, ibdev->node_desc, sizeof(smp->data));
	return reply(smp);
}

static int subn_get_nodeinfo(struct ib_smp *smp, struct ib_device *ibdev,
			     u8 port)
{
	struct ib_node_info *nip = (struct ib_node_info *)&smp->data;
	unsigned pidx = port - 1; /* IB number port from 1, hdw from 0 */

	if (smp->attr_mod || pidx >= 1)
		smp->status |= IB_SMP_INVALID_FIELD;
	else
		nip->port_guid = ibdev->node_guid;

	nip->base_version = 1;
	nip->class_version = 1;
	nip->node_type = 1;     /* channel adapter */
	nip->num_ports = 1;
	/* This is already in network order */
	nip->sys_guid = 0;
	nip->node_guid = ibdev->node_guid;
	nip->partition_cap = cpu_to_be16(1);
	nip->device_id = 0;
	nip->revision = 0;
	nip->local_port_num = port;
	nip->vendor_id[0] = 0;
	nip->vendor_id[1] = 0;
	nip->vendor_id[2] = 0;
	return reply(smp);
}

static int subn_get_portinfo(struct ib_smp *smp, struct ib_device *ibdev,
			     u8 port)
{
	// struct qib_devdata *dd;
	// struct qib_pportdata *ppd;
	// struct qib_ibport *ibp;
	struct isbdm_device *sdev = to_isbdm_dev(ibdev);
	struct ib_port_info *pip = (struct ib_port_info *)smp->data;
	int ret;
	u32 port_num = be32_to_cpu(smp->attr_mod);

	if (port_num != 0) {
		if (port_num > 1) {
			smp->status |= IB_SMP_INVALID_FIELD;
			ret = reply(smp);
			goto bail;
		}
	}

	// dd = dd_from_ibdev(ibdev);
	// /* IB numbers ports from 1, hdw from 0 */
	// ppd = dd->pport + (port_num - 1);
	// ibp = &ppd->ibport_data;

	/* Clear all fields.  Only set the non-zero fields. */
	memset(smp->data, 0, sizeof(smp->data));

	/* Only return the mkey if the protection field allows it. */
	// if (!(smp->method == IB_MGMT_METHOD_GET &&
	//       ibp->rvp.mkey != smp->mkey &&
	//       ibp->rvp.mkeyprot == 1))
	// 	pip->mkey = ibp->rvp.mkey;
	// pip->gid_prefix = ibp->rvp.gid_prefix;
	pip->lid = cpu_to_be16(sdev->lid);
	pip->sm_lid = cpu_to_be16(sdev->lid);
	pip->cap_mask = cpu_to_be32(IB_PORT_SYS_IMAGE_GUID_SUP |
		IB_PORT_CLIENT_REG_SUP | IB_PORT_SL_MAP_SUP |
		IB_PORT_TRAP_SUP | IB_PORT_AUTO_MIGR_SUP |
		IB_PORT_DR_NOTICE_SUP | IB_PORT_CAP_MASK_NOTICE_SUP |
		IB_PORT_OTHER_LOCAL_CHANGES_SUP);
	/* pip->diag_code; */
	// pip->mkey_lease_period = cpu_to_be16(ibp->rvp.mkey_lease_period);
	pip->local_port_num = port;
	// pip->link_width_enabled = ppd->link_width_enabled;
	// pip->link_width_supported = ppd->link_width_supported;
	// pip->link_width_active = ppd->link_width_active;
	// state = dd->f_iblink_state(ppd->lastibcstat);
	// pip->linkspeed_portstate = ppd->link_speed_supported << 4 | state;

	// pip->portphysstate_linkdown =
	// 	(dd->f_ibphys_portstate(ppd->lastibcstat) << 4) |
	// 	(get_linkdowndefaultstate(ppd) ? 1 : 2);
	// pip->mkeyprot_resv_lmc = (ibp->rvp.mkeyprot << 6) | ppd->lmc;
	// pip->linkspeedactive_enabled = (ppd->link_speed_active << 4) |
	// 	ppd->link_speed_enabled;
	// switch (ppd->ibmtu) {
	// default: /* something is wrong; fall through */
	// case 4096:
	// 	mtu = IB_MTU_4096;
	// 	break;
	// case 2048:
	// 	mtu = IB_MTU_2048;
	// 	break;
	// case 1024:
	// 	mtu = IB_MTU_1024;
	// 	break;
	// case 512:
	// 	mtu = IB_MTU_512;
	// 	break;
	// case 256:
	// 	mtu = IB_MTU_256;
	// 	break;
	// }
	pip->neighbormtu_mastersmsl = (IB_MTU_4096 << 4); // | ibp->rvp.sm_sl;
	// pip->vlcap_inittype = ppd->vls_supported << 4;  /* InitType = 0 */
	// pip->vl_high_limit = ibp->rvp.vl_high_limit;
	// pip->vl_arb_high_cap =
	// 	dd->f_get_ib_cfg(ppd, QIB_IB_CFG_VL_HIGH_CAP);
	// pip->vl_arb_low_cap =
	// 	dd->f_get_ib_cfg(ppd, QIB_IB_CFG_VL_LOW_CAP);
	// /* InitTypeReply = 0 */
	// pip->inittypereply_mtucap = qib_ibmtu ? qib_ibmtu : IB_MTU_4096;
	pip->inittypereply_mtucap = IB_MTU_4096;
	/* HCAs ignore VLStallCount and HOQLife */
	/* pip->vlstallcnt_hoqlife; */
	// pip->operationalvl_pei_peo_fpi_fpo =
	// 	dd->f_get_ib_cfg(ppd, QIB_IB_CFG_OP_VLS) << 4;
	// pip->mkey_violations = cpu_to_be16(ibp->rvp.mkey_violations);
	/* P_KeyViolations are counted by hardware. */
	// pip->pkey_violations = cpu_to_be16(ibp->rvp.pkey_violations);
	// pip->qkey_violations = cpu_to_be16(ibp->rvp.qkey_violations);
	/* Only the hardware GUID is supported for now */
	pip->guid_cap = 1;
	// pip->clientrereg_resv_subnetto = ibp->rvp.subnet_timeout;
	/* 32.768 usec. response time (guessing) */
	pip->resv_resptimevalue = 3;
	// pip->localphyerrors_overrunerrors =
	// 	(get_phyerrthreshold(ppd) << 4) |
	// 	get_overrunthreshold(ppd);
	/* pip->max_credit_hint; */
	// if (ibp->rvp.port_cap_flags & IB_PORT_LINK_LATENCY_SUP) {
	// 	u32 v;

	// 	v = dd->f_get_ib_cfg(ppd, QIB_IB_CFG_LINKLATENCY);
	// 	pip->link_roundtrip_latency[0] = v >> 16;
	// 	pip->link_roundtrip_latency[1] = v >> 8;
	// 	pip->link_roundtrip_latency[2] = v;
	// }

	ret = reply(smp);

bail:
	return ret;
}

static int subn_get_pkeytable(struct ib_smp *smp, struct ib_device *ibdev,
			      u8 port)
{
	u32 startpx = 32 * (be32_to_cpu(smp->attr_mod) & 0xffff);
	// u16 *p = (u16 *) smp->data;
	__be16 *q = (__be16 *) smp->data;

	/* 64 blocks of 32 16-bit P_Key entries */

	memset(smp->data, 0, sizeof(smp->data));
	if (startpx == 0) {
		q[0] = cpu_to_be16(0xffff);
	} else {
		smp->status |= IB_SMP_INVALID_FIELD;
	}

	return reply(smp);
}

static void isbdm_set_lid(struct isbdm_device *sdev, u32 lid, u8 lmc)
{
	sdev->lid = lid;
	sdev->lmc = lmc;
	isbdm_dbg(&sdev->base_dev, "Got a lid: 0x%x\n", lid);
}

/**
 * subn_set_portinfo - set port information
 * @smp: the incoming SM packet
 * @ibdev: the infiniband device
 * @port: the port on the device
 *
 * Set Portinfo (see ch. 14.2.5.6).
 */
static int subn_set_portinfo(struct ib_smp *smp, struct ib_device *ibdev,
			     u8 port)
{
	struct ib_port_info *pip = (struct ib_port_info *)smp->data;
	struct ib_event event;
	// struct qib_devdata *dd;
	// struct qib_pportdata *ppd;
	// struct qib_ibport *ibp;
	struct isbdm_device *sdev = to_isbdm_dev(ibdev);
	// u8 clientrereg = (pip->clientrereg_resv_subnetto & 0x80);
	// unsigned long flags;
	u16 lid;
	u16 sm_lid;
	// u8 lwe;
	// u8 lse;
	// u8 state;
	// u8 vls;
	u8 msl;
	// u16 lstate;
	// int ore, mtu;
	int ret;
	u32 port_num = be32_to_cpu(smp->attr_mod);

	if (port_num != 0) {
		if (port_num > 1)
			goto err;
		/* Port attributes can only be set on the receiving port */
		if (port_num != port)
			goto get_only;
	}

	// dd = dd_from_ibdev(ibdev);
	// /* IB numbers ports from 1, hdw from 0 */
	// ppd = dd->pport + (port_num - 1);
	// ibp = &ppd->ibport_data;
	event.device = ibdev;
	event.element.port_num = port;

	// ibp->rvp.mkey = pip->mkey;
	// ibp->rvp.gid_prefix = pip->gid_prefix;
	// ibp->rvp.mkey_lease_period = be16_to_cpu(pip->mkey_lease_period);

	lid = be16_to_cpu(pip->lid);
	/* Must be a valid unicast LID address. */
	if (lid == 0 || lid >= be16_to_cpu(IB_MULTICAST_LID_BASE)) {
		smp->status |= IB_SMP_INVALID_FIELD;

	} else if ((sdev->lid != lid) ||
		   (sdev->lmc != (pip->mkeyprot_resv_lmc & 7))) {

		// if (sdev->lid != lid)
		// 	qib_set_uevent_bits(ppd, _QIB_EVENT_LID_CHANGE_BIT);

		// if (sdev->lmc != (pip->mkeyprot_resv_lmc & 7))
		// 	qib_set_uevent_bits(ppd, _QIB_EVENT_LMC_CHANGE_BIT);

		isbdm_set_lid(sdev, lid, pip->mkeyprot_resv_lmc & 7);
		event.event = IB_EVENT_LID_CHANGE;
		ib_dispatch_event(&event);
	}

	sm_lid = be16_to_cpu(pip->sm_lid);
	msl = pip->neighbormtu_mastersmsl & 0xF;
	/* Must be a valid unicast LID address. */
	if (sm_lid == 0 || sm_lid >= be16_to_cpu(IB_MULTICAST_LID_BASE)) {
		smp->status |= IB_SMP_INVALID_FIELD;

	} else if (sm_lid != sdev->sm_lid || msl != sdev->sm_sl) {
		// spin_lock_irqsave(&ibp->rvp.lock, flags);
		// if (ibp->rvp.sm_ah) {
		// 	if (smlid != ibp->rvp.sm_lid)
		// 		rdma_ah_set_dlid(&ibp->rvp.sm_ah->attr,
		// 				 smlid);
		// 	if (msl != ibp->rvp.sm_sl)
		// 		rdma_ah_set_sl(&ibp->rvp.sm_ah->attr, msl);
		// }
		// spin_unlock_irqrestore(&ibp->rvp.lock, flags);
		if (sm_lid != sdev->sm_lid)
			sdev->sm_lid = sm_lid;

		if (msl != sdev->sm_sl)
			sdev->sm_sl = msl;

		event.event = IB_EVENT_SM_CHANGE;
		ib_dispatch_event(&event);
	}

	// /* Allow 1x or 4x to be set (see 14.2.6.6). */
	// lwe = pip->link_width_enabled;
	// if (lwe) {
	// 	if (lwe == 0xFF)
	// 		set_link_width_enabled(ppd, ppd->link_width_supported);
	// 	else if (lwe >= 16 || (lwe & ~ppd->link_width_supported))
	// 		smp->status |= IB_SMP_INVALID_FIELD;
	// 	else if (lwe != ppd->link_width_enabled)
	// 		set_link_width_enabled(ppd, lwe);
	// }

	// lse = pip->linkspeedactive_enabled & 0xF;
	// if (lse) {
	// 	/*
	// 	 * The IB 1.2 spec. only allows link speed values
	// 	 * 1, 3, 5, 7, 15.  1.2.1 extended to allow specific
	// 	 * speeds.
	// 	 */
	// 	if (lse == 15)
	// 		set_link_speed_enabled(ppd,
	// 				       ppd->link_speed_supported);
	// 	else if (lse >= 8 || (lse & ~ppd->link_speed_supported))
	// 		smp->status |= IB_SMP_INVALID_FIELD;
	// 	else if (lse != ppd->link_speed_enabled)
	// 		set_link_speed_enabled(ppd, lse);
	// }

	// /* Set link down default state. */
	// switch (pip->portphysstate_linkdown & 0xF) {
	// case 0: /* NOP */
	// 	break;
	// case 1: /* SLEEP */
	// 	(void) dd->f_set_ib_cfg(ppd, QIB_IB_CFG_LINKDEFAULT,
	// 				IB_LINKINITCMD_SLEEP);
	// 	break;
	// case 2: /* POLL */
	// 	(void) dd->f_set_ib_cfg(ppd, QIB_IB_CFG_LINKDEFAULT,
	// 				IB_LINKINITCMD_POLL);
	// 	break;
	// default:
	// 	smp->status |= IB_SMP_INVALID_FIELD;
	// }

	// ibp->rvp.mkeyprot = pip->mkeyprot_resv_lmc >> 6;
	// ibp->rvp.vl_high_limit = pip->vl_high_limit;
	// (void) dd->f_set_ib_cfg(ppd, QIB_IB_CFG_VL_HIGH_LIMIT,
	// 			    ibp->rvp.vl_high_limit);

	// mtu = ib_mtu_enum_to_int((pip->neighbormtu_mastersmsl >> 4) & 0xF);
	// if (mtu == -1)
	// 	smp->status |= IB_SMP_INVALID_FIELD;
	// else
	// 	qib_set_mtu(ppd, mtu);

	// /* Set operational VLs */
	// vls = (pip->operationalvl_pei_peo_fpi_fpo >> 4) & 0xF;
	// if (vls) {
	// 	if (vls > ppd->vls_supported)
	// 		smp->status |= IB_SMP_INVALID_FIELD;
	// 	else
	// 		(void) dd->f_set_ib_cfg(ppd, QIB_IB_CFG_OP_VLS, vls);
	// }

	// if (pip->mkey_violations == 0)
	// 	ibp->rvp.mkey_violations = 0;

	// if (pip->pkey_violations == 0)
	// 	ibp->rvp.pkey_violations = 0;

	// if (pip->qkey_violations == 0)
	// 	ibp->rvp.qkey_violations = 0;

	// ore = pip->localphyerrors_overrunerrors;
	// if (set_phyerrthreshold(ppd, (ore >> 4) & 0xF))
	// 	smp->status |= IB_SMP_INVALID_FIELD;

	// if (set_overrunthreshold(ppd, (ore & 0xF)))
	// 	smp->status |= IB_SMP_INVALID_FIELD;

	// ibp->rvp.subnet_timeout = pip->clientrereg_resv_subnetto & 0x1F;

	// /*
	//  * Do the port state change now that the other link parameters
	//  * have been set.
	//  * Changing the port physical state only makes sense if the link
	//  * is down or is being set to down.
	//  */
	// state = pip->linkspeed_portstate & 0xF;
	// lstate = (pip->portphysstate_linkdown >> 4) & 0xF;
	// if (lstate && !(state == IB_PORT_DOWN || state == IB_PORT_NOP))
	// 	smp->status |= IB_SMP_INVALID_FIELD;

	// /*
	//  * Only state changes of DOWN, ARM, and ACTIVE are valid
	//  * and must be in the correct state to take effect (see 7.2.6).
	//  */
	// switch (state) {
	// case IB_PORT_NOP:
	// 	if (lstate == 0)
	// 		break;
	// 	fallthrough;
	// case IB_PORT_DOWN:
	// 	if (lstate == 0)
	// 		lstate = QIB_IB_LINKDOWN_ONLY;
	// 	else if (lstate == 1)
	// 		lstate = QIB_IB_LINKDOWN_SLEEP;
	// 	else if (lstate == 2)
	// 		lstate = QIB_IB_LINKDOWN;
	// 	else if (lstate == 3)
	// 		lstate = QIB_IB_LINKDOWN_DISABLE;
	// 	else {
	// 		smp->status |= IB_SMP_INVALID_FIELD;
	// 		break;
	// 	}
	// 	spin_lock_irqsave(&ppd->lflags_lock, flags);
	// 	ppd->lflags &= ~QIBL_LINKV;
	// 	spin_unlock_irqrestore(&ppd->lflags_lock, flags);
	// 	qib_set_linkstate(ppd, lstate);
	// 	/*
	// 	 * Don't send a reply if the response would be sent
	// 	 * through the disabled port.
	// 	 */
	// 	if (lstate == QIB_IB_LINKDOWN_DISABLE && smp->hop_cnt) {
	// 		ret = IB_MAD_RESULT_SUCCESS | IB_MAD_RESULT_CONSUMED;
	// 		goto done;
	// 	}
	// 	qib_wait_linkstate(ppd, QIBL_LINKV, 10);
	// 	break;
	// case IB_PORT_ARMED:
	// 	qib_set_linkstate(ppd, QIB_IB_LINKARM);
	// 	break;
	// case IB_PORT_ACTIVE:
	// 	qib_set_linkstate(ppd, QIB_IB_LINKACTIVE);
	// 	break;
	// default:
	// 	smp->status |= IB_SMP_INVALID_FIELD;
	// }

	// if (clientrereg) {
	// 	event.event = IB_EVENT_CLIENT_REREGISTER;
	// 	ib_dispatch_event(&event);
	// }

	// /* restore re-reg bit per o14-12.2.1 */
	// pip->clientrereg_resv_subnetto |= clientrereg;

	goto get_only;

err:
	smp->status |= IB_SMP_INVALID_FIELD;
get_only:
	ret = subn_get_portinfo(smp, ibdev, port);
// done:
	return ret;
}

static int subn_trap_repress(struct ib_smp *smp, struct ib_device *ibdev,
			     u8 port)
{
	/*
	 * For now, we only send the trap once so no need to process this.
	 * o13-6, o13-7,
	 * o14-3.a4 The SMA shall not send any message in response to a valid
	 * SubnTrapRepress() message.
	 */
	return IB_MAD_RESULT_SUCCESS | IB_MAD_RESULT_CONSUMED;
}

static int process_subn(struct ib_device *ibdev, int mad_flags,
			u8 port, const struct ib_mad *in_mad,
			struct ib_mad *out_mad)
{
	struct ib_smp *smp = (struct ib_smp *)out_mad;
	struct isbdm_device *sdev = to_isbdm_dev(ibdev);
	//struct qib_ibport *ibp = to_iport(ibdev, port);
	//struct qib_pportdata *ppd = ppd_from_ibp(ibp);
	int ret;

	*out_mad = *in_mad;
	if (smp->class_version != 1) {
		smp->status |= IB_SMP_UNSUP_VERSION;
		ret = reply(smp);
		goto bail;
	}

	/* TODO: Check the management key! */
	// ret = check_mkey(ibp, smp, mad_flags);
	// if (ret) {
	// 	u32 port_num = be32_to_cpu(smp->attr_mod);

	// 	/*
	// 	 * If this is a get/set portinfo, we already check the
	// 	 * M_Key if the MAD is for another port and the M_Key
	// 	 * is OK on the receiving port. This check is needed
	// 	 * to increment the error counters when the M_Key
	// 	 * fails to match on *both* ports.
	// 	 */
	// 	if (in_mad->mad_hdr.attr_id == IB_SMP_ATTR_PORT_INFO &&
	// 	    (smp->method == IB_MGMT_METHOD_GET ||
	// 	     smp->method == IB_MGMT_METHOD_SET) &&
	// 	    port_num && port_num <= ibdev->phys_port_cnt &&
	// 	    port != port_num)
	// 		(void) check_mkey(to_iport(ibdev, port_num), smp, 0);
	// 	ret = IB_MAD_RESULT_FAILURE;
	// 	goto bail;
	// }

	switch (smp->method) {
	case IB_MGMT_METHOD_GET:
		switch (smp->attr_id) {
		case IB_SMP_ATTR_NODE_DESC:
			ret = subn_get_nodedescription(smp, ibdev);
			goto bail;
		case IB_SMP_ATTR_NODE_INFO:
			ret = subn_get_nodeinfo(smp, ibdev, port);
			goto bail;
		// case IB_SMP_ATTR_GUID_INFO:
		// 	ret = subn_get_guidinfo(smp, ibdev, port);
		// 	goto bail;
		case IB_SMP_ATTR_PORT_INFO:
			ret = subn_get_portinfo(smp, ibdev, port);
			goto bail;
		case IB_SMP_ATTR_PKEY_TABLE:
			ret = subn_get_pkeytable(smp, ibdev, port);
			goto bail;
		// case IB_SMP_ATTR_SL_TO_VL_TABLE:
		// 	ret = subn_get_sl_to_vl(smp, ibdev, port);
		// 	goto bail;
		// case IB_SMP_ATTR_VL_ARB_TABLE:
		// 	ret = subn_get_vl_arb(smp, ibdev, port);
		// 	goto bail;
		case IB_SMP_ATTR_SM_INFO:
		// 	if (ibp->rvp.port_cap_flags & IB_PORT_SM_DISABLED) {
		// 		ret = IB_MAD_RESULT_SUCCESS |
		// 			IB_MAD_RESULT_CONSUMED;
		// 		goto bail;
		// 	}
		// 	if (ibp->rvp.port_cap_flags & IB_PORT_SM) {
				ret = IB_MAD_RESULT_SUCCESS;
				goto bail;
		// 	}
		// 	fallthrough;
		default:
			dev_warn(&sdev->ii->pdev->dev,
				 "Unsupported METHOD_GET %x\n",
				 smp->attr_id);

			smp->status |= IB_SMP_UNSUP_METH_ATTR;
			ret = reply(smp);
			goto bail;
		}

	case IB_MGMT_METHOD_SET:
		switch (smp->attr_id) {
		// case IB_SMP_ATTR_GUID_INFO:
		// 	ret = subn_set_guidinfo(smp, ibdev, port);
		// 	goto bail;
		case IB_SMP_ATTR_PORT_INFO:
			ret = subn_set_portinfo(smp, ibdev, port);
			goto bail;
		// case IB_SMP_ATTR_PKEY_TABLE:
		// 	ret = subn_set_pkeytable(smp, ibdev, port);
		// 	goto bail;
		// case IB_SMP_ATTR_SL_TO_VL_TABLE:
		// 	ret = subn_set_sl_to_vl(smp, ibdev, port);
		// 	goto bail;
		// case IB_SMP_ATTR_VL_ARB_TABLE:
		// 	ret = subn_set_vl_arb(smp, ibdev, port);
		// 	goto bail;
		case IB_SMP_ATTR_SM_INFO:
		// 	if (ibp->rvp.port_cap_flags & IB_PORT_SM_DISABLED) {
		// 		ret = IB_MAD_RESULT_SUCCESS |
		// 			IB_MAD_RESULT_CONSUMED;
		// 		goto bail;
		// 	}
		// 	if (ibp->rvp.port_cap_flags & IB_PORT_SM) {
				ret = IB_MAD_RESULT_SUCCESS;
				goto bail;
		// 	}
		// 	fallthrough;
		default:
			dev_warn(&sdev->ii->pdev->dev,
				 "Unsupported METHOD_SET %x\n",
				 smp->attr_id);

			smp->status |= IB_SMP_UNSUP_METH_ATTR;
			ret = reply(smp);
			goto bail;
		}

	case IB_MGMT_METHOD_TRAP_REPRESS:
		if (smp->attr_id == IB_SMP_ATTR_NOTICE) {
			ret = subn_trap_repress(smp, ibdev, port);

		} else {
			smp->status |= IB_SMP_UNSUP_METH_ATTR;
			ret = reply(smp);
		}

		goto bail;

	case IB_MGMT_METHOD_TRAP:
	case IB_MGMT_METHOD_REPORT:
	case IB_MGMT_METHOD_REPORT_RESP:
	case IB_MGMT_METHOD_GET_RESP:
		/*
		 * The ib_mad module will call us to process responses
		 * before checking for other consumers.
		 * Just tell the caller to process it normally.
		 */
		ret = IB_MAD_RESULT_SUCCESS;
		goto bail;

	case IB_MGMT_METHOD_SEND:
	// 	if (ib_get_smp_direction(smp) &&
	// 	    smp->attr_id == QIB_VENDOR_IPG) {
	// 		ppd->dd->f_set_ib_cfg(ppd, QIB_IB_CFG_PORT,
	// 				      smp->data[0]);
	// 		ret = IB_MAD_RESULT_SUCCESS | IB_MAD_RESULT_CONSUMED;
	// 	} else
			ret = IB_MAD_RESULT_SUCCESS;
		goto bail;

	default:
		dev_warn(&sdev->ii->pdev->dev,
			 "Unsupported method %x\n",
			 smp->method);

		smp->status |= IB_SMP_UNSUP_METHOD;
		ret = reply(smp);
	}

bail:
	return ret;
}

/**
 * isbdm_process_mad - process an incoming MAD packet
 * @ibdev: the infiniband device this packet came in on
 * @mad_flags: MAD flags
 * @port: the port number this packet came in on
 * @in_wc: the work completion entry for this packet
 * @in_grh: the global route header for this packet
 * @in: the incoming MAD
 * @out: any outgoing MAD reply
 * @out_mad_size: size of the outgoing MAD reply
 * @out_mad_pkey_index: unused
 *
 * Returns IB_MAD_RESULT_SUCCESS if this is a MAD that we are not
 * interested in processing.
 *
 * Note that the verbs framework has already done the MAD sanity checks,
 * and hop count/pointer updating for IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE
 * MADs.
 *
 * This is called by the ib_mad module.
 */
int isbdm_process_mad(struct ib_device *ibdev, int mad_flags, u32 port,
		      const struct ib_wc *in_wc, const struct ib_grh *in_grh,
		      const struct ib_mad *in, struct ib_mad *out,
		      size_t *out_mad_size, u16 *out_mad_pkey_index)
{
	int ret;

	switch (in->mad_hdr.mgmt_class) {
	case IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE:
	case IB_MGMT_CLASS_SUBN_LID_ROUTED:
		ret = process_subn(ibdev, mad_flags, port, in, out);
		goto bail;

	// case IB_MGMT_CLASS_PERF_MGMT:
	// 	ret = process_perf(ibdev, port, in, out);
	// 	goto bail;

	// case IB_MGMT_CLASS_CONG_MGMT:
	// 	if (!ppd->congestion_entries_shadow ||
	// 		 !qib_cc_table_size) {
	// 		ret = IB_MAD_RESULT_SUCCESS;
	// 		goto bail;
	// 	}
	// 	ret = process_cc(ibdev, mad_flags, port, in, out);
	// 	goto bail;

	default:
		ret = IB_MAD_RESULT_SUCCESS;
	}

bail:
	return ret;
}
