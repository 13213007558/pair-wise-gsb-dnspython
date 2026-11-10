# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Apply DNS UPDATE messages to a transaction manager.

This module implements the server-side processing of RFC 2136 dynamic
updates, but it does not include any name service or network functionality.
An :py:class:`dns.update.UpdateMessage` is validated and applied to an
in-memory zone (or, more generally, any
:py:class:`dns.transaction.TransactionManager`), making the module suitable
for offline validation and policy testing.

The whole update runs inside a single writer transaction.  Prerequisites
are evaluated against the transaction's pre-update snapshot before any
mutation, and the update is either committed in full or rolled back so
that a failed update never leaves a partially modified zone.

TSIG authentication is deliberately out of scope.  The caller is
responsible for authenticating the message before calling this module;
the key name carried by an UpdateMessage is never treated as
authorization.  A trusted admission callback may be supplied as
*transaction_setup* to constrain what the transaction may do; any
exception it raises aborts and rolls back the update.
"""

from collections.abc import Callable

import dns.exception
import dns.name
import dns.node
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.transaction
import dns.ttl
import dns.update


class UpdateError(dns.exception.DNSException):
    """An RFC 2136 update could not be applied.

    The :attr:`rcode` attribute holds the DNS RCODE that an authoritative
    server would return in its response for this failure.
    """

    def __init__(self, rcode: dns.rcode.Rcode | str, message: str | None = None):
        self.rcode = dns.rcode.Rcode.make(rcode)
        if message is None:
            message = dns.rcode.to_text(self.rcode)
        super().__init__(message)


def _validate_zone_section(
    update_message: dns.update.UpdateMessage,
    txn_manager: dns.transaction.TransactionManager,
) -> tuple[dns.name.Name, dns.rdataclass.RdataClass]:
    """Check the zone section and the manager's class.

    Returns the absolute zone origin and the zone's rdata class.
    """
    zone_section = update_message.zone
    if len(zone_section) != 1:
        raise UpdateError(dns.rcode.FORMERR, "update must name exactly one zone")
    zone_rrset = zone_section[0]
    if zone_rrset.rdtype != dns.rdatatype.SOA:
        raise UpdateError(dns.rcode.FORMERR, "zone section must name type SOA")
    zone_name = zone_rrset.name
    if not zone_name.is_absolute():
        raise UpdateError(dns.rcode.FORMERR, "zone name must be absolute")
    manager_origin, _, _ = txn_manager.origin_information()
    if manager_origin is None:
        raise UpdateError(dns.rcode.SERVFAIL, "transaction manager has no origin")
    if zone_name != manager_origin:
        raise UpdateError(dns.rcode.NOTAUTH, f"not authoritative for zone {zone_name}")
    zone_class = txn_manager.get_class()
    if zone_rrset.rdclass != zone_class:
        raise UpdateError(
            dns.rcode.NOTAUTH, "update zone class does not match the zone"
        )
    return zone_name, zone_class


def _absolute_name(name: dns.name.Name, origin: dns.name.Name) -> dns.name.Name:
    """Derive the absolute form of *name* and require it to be in *origin*."""
    if name.is_absolute():
        absolute_name = name
    else:
        absolute_name = name.derelativize(origin)
    if not absolute_name.is_subdomain(origin):
        raise UpdateError(dns.rcode.NOTZONE, f"name {absolute_name} is not in the zone")
    return absolute_name


def _txn_name(
    absolute_name: dns.name.Name,
    origin: dns.name.Name,
    relativize: bool,
) -> dns.name.Name:
    """Return the name form expected by the transaction manager.

    Zone scope and apex checks always use absolute names, but transaction
    reads and writes use the manager's relativity setting.
    """
    if relativize:
        return absolute_name.relativize(origin)
    return absolute_name


def _check_name_scope(
    update_message: dns.update.UpdateMessage, origin: dns.name.Name
) -> None:
    """Check that every name in the prerequisite and update sections is in zone."""
    for rrset in update_message.prerequisite:
        _absolute_name(rrset.name, origin)
    for rrset in update_message.update:
        _absolute_name(rrset.name, origin)


def _meta_class(rrset: dns.rrset.RRset) -> dns.rdataclass.RdataClass:
    """Return the metaclass (ANY/NONE) marking an operation, if any.

    Builder-created messages store ANY/NONE in the rrset class, while parsed
    messages rewrite the class to the zone class and keep the metaclass in
    the rrset's ``deleting`` attribute.
    """
    if rrset.deleting is not None:
        return rrset.deleting
    return rrset.rdclass


def _check_prerequisites(
    update_message: dns.update.UpdateMessage,
    txn: dns.transaction.Transaction,
    origin: dns.name.Name,
    relativize: bool,
) -> None:
    """Evaluate every prerequisite against the pre-update snapshot in *txn*.

    Implements the five prerequisite forms of RFC 2136 sections 2.4.3 and
    2.4.4.  Value-dependent prerequisites compare rdata only; the TTL is not
    part of RRset equality, per the RFC's requirement that prerequisite TTLs
    be zero.
    """
    for rrset in update_message.prerequisite:
        absolute_name = _absolute_name(rrset.name, origin)
        name = _txn_name(absolute_name, origin, relativize)
        metaclass = _meta_class(rrset)
        if metaclass == dns.rdataclass.ANY:
            if len(rrset) != 0:
                raise UpdateError(
                    dns.rcode.FORMERR, "ANY prerequisite must not carry rdata"
                )
            if rrset.rdtype == dns.rdatatype.NONE:
                raise UpdateError(
                    dns.rcode.FORMERR,
                    "ANY class prerequisite cannot use type NONE",
                )
            if rrset.rdtype == dns.rdatatype.ANY:
                # A name is in use.
                if not txn.name_exists(name):
                    raise UpdateError(dns.rcode.NXDOMAIN, "prerequisite name absent")
            else:
                # An rrset of the given type is in use.
                rdataset = txn.get(name, rrset.rdtype, rrset.covers)
                if rdataset is None:
                    raise UpdateError(dns.rcode.NXRRSET, "prerequisite rrset absent")
        elif metaclass == dns.rdataclass.NONE:
            if len(rrset) != 0:
                raise UpdateError(
                    dns.rcode.FORMERR, "NONE prerequisite must not carry rdata"
                )
            if rrset.rdtype == dns.rdatatype.NONE:
                raise UpdateError(
                    dns.rcode.FORMERR,
                    "NONE class prerequisite cannot use type NONE",
                )
            if rrset.rdtype == dns.rdatatype.ANY:
                # A name is not in use.
                if txn.name_exists(name):
                    raise UpdateError(dns.rcode.YXDOMAIN, "prerequisite name present")
            else:
                # An rrset of the given type is not in use.
                rdataset = txn.get(name, rrset.rdtype, rrset.covers)
                if rdataset is not None:
                    raise UpdateError(dns.rcode.YXRRSET, "prerequisite rrset present")
        else:
            # Value-dependent prerequisite: every specified rdata must be active.
            if len(rrset) == 0:
                raise UpdateError(
                    dns.rcode.FORMERR, "value prerequisite must carry rdata"
                )
            rdataset = txn.get(name, rrset.rdtype, rrset.covers)
            if rdataset is None:
                raise UpdateError(dns.rcode.NXRRSET, "prerequisite rrset absent")
            for rdata in rrset:
                # Rdata comparison ignores the TTL, which is not stored on an
                # Rdata object and is not part of RRset value equality.
                if rdata not in rdataset:
                    raise UpdateError(
                        dns.rcode.NXRRSET, "prerequisite rdata not active"
                    )


def _check_cname_conflict(
    txn: dns.transaction.Transaction,
    name: dns.name.Name,
    rrset: dns.rrset.RRset,
) -> None:
    """Reject mixing a CNAME with other data at a node (RFC 2136 section 3.4.2).

    The node classification treats NSEC/NSEC3/KEY and RRSIG records as
    neutral, so they may coexist with a CNAME.
    """
    rdataset_kind = dns.node.NodeKind.classify_rdataset(rrset)
    node = txn.get_node(name)
    if node is None:
        return
    node_kind = node.classify()
    if (
        node_kind == dns.node.NodeKind.CNAME
        and rdataset_kind == dns.node.NodeKind.REGULAR
    ):
        raise UpdateError(dns.rcode.YXRRSET, "cannot add other data to a CNAME node")
    if (
        node_kind == dns.node.NodeKind.REGULAR
        and rdataset_kind == dns.node.NodeKind.CNAME
    ):
        raise UpdateError(
            dns.rcode.YXRRSET, "cannot add a CNAME to a node with other data"
        )


def _check_apex(
    txn: dns.transaction.Transaction,
    origin: dns.name.Name,
    relativize: bool,
) -> None:
    """Ensure the apex still has an SOA and an NS rrset after the update.

    RFC 2136 section 3.4.3 forbids removing the apex SOA or NS, but a request
    may delete them and re-add replacement records within the same update, so
    the rule is checked against the resulting state rather than per RR.
    """
    apex_name = _txn_name(origin, origin, relativize)
    for rdtype in (dns.rdatatype.SOA, dns.rdatatype.NS):
        rdataset = txn.get(apex_name, rdtype)
        if rdataset is None or len(rdataset) == 0:
            raise UpdateError(
                dns.rcode.REFUSED,
                f"the zone apex must retain an {dns.rdatatype.to_text(rdtype)} rrset",
            )


def _apply_updates(
    update_message: dns.update.UpdateMessage,
    txn: dns.transaction.Transaction,
    origin: dns.name.Name,
    zone_class: dns.rdataclass.RdataClass,
    relativize: bool,
) -> None:
    """Apply the update section in message order (RFC 2136 section 3.4)."""
    apex_may_change = False
    for rrset in update_message.update:
        absolute_name = _absolute_name(rrset.name, origin)
        name = _txn_name(absolute_name, origin, relativize)
        metaclass = _meta_class(rrset)
        if metaclass == dns.rdataclass.ANY:
            # Delete an rrset, or delete a whole name when the type is ANY.
            if len(rrset) != 0:
                raise UpdateError(dns.rcode.FORMERR, "ANY delete must not carry rdata")
            if absolute_name == origin and rrset.rdtype in (
                dns.rdatatype.ANY,
                dns.rdatatype.SOA,
                dns.rdatatype.NS,
            ):
                # Deletion of apex data is only legal if the same update
                # restores it; the final state is checked below.
                apex_may_change = True
            if rrset.rdtype == dns.rdatatype.ANY:
                txn.delete(name)
            else:
                txn.delete(name, rrset.rdtype, rrset.covers)
        elif metaclass == dns.rdataclass.NONE:
            # Delete the specified rdata only; it is not an error if some of
            # the rdata is absent (RFC 2136 section 3.4.2).
            if len(rrset) == 0:
                raise UpdateError(dns.rcode.FORMERR, "NONE delete must carry rdata")
            if absolute_name == origin and rrset.rdtype in (
                dns.rdatatype.SOA,
                dns.rdatatype.NS,
            ):
                apex_may_change = True
            txn.delete(name, rrset.to_rdataset())
        else:
            # Add rdata to an rrset.
            if rrset.rdclass != zone_class:
                raise UpdateError(dns.rcode.FORMERR, "added rrset has the wrong class")
            if rrset.rdtype in (dns.rdatatype.ANY, dns.rdatatype.NONE):
                raise UpdateError(
                    dns.rcode.FORMERR, "ANY or NONE types cannot be added"
                )
            if rrset.ttl < 0 or rrset.ttl > dns.ttl.MAX_TTL:
                raise UpdateError(dns.rcode.FORMERR, "invalid TTL")
            if rrset.rdtype == dns.rdatatype.SOA and absolute_name != origin:
                raise UpdateError(
                    dns.rcode.FORMERR, "only the zone apex may have an SOA"
                )
            _check_cname_conflict(txn, name, rrset)
            existing = txn.get(name, rrset.rdtype, rrset.covers)
            if existing is not None and existing.ttl != rrset.ttl:
                raise UpdateError(
                    dns.rcode.SERVFAIL,
                    "added rrset TTL differs from the existing rrset TTL",
                )
            txn.add(name, rrset.to_rdataset())
    if apex_may_change:
        _check_apex(txn, origin, relativize)


def apply(
    update_message: dns.update.UpdateMessage,
    txn_manager: dns.transaction.TransactionManager,
    transaction_setup: Callable[[dns.transaction.Transaction], None] | None = None,
) -> None:
    """Apply an RFC 2136 DNS UPDATE to *txn_manager*.

    The zone section, rdata class and the zone scope of every name are
    checked first.  All prerequisites are then evaluated against the same
    pre-update snapshot of a single writer transaction, and only if every
    prerequisite holds is the update section applied in request order.  The
    transaction commits when the whole update succeeded; any failure rolls
    it back, so the managed zone is never left partially updated.

    TSIG authentication is the caller's responsibility.  This function never
    consults the message's TSIG key name for authorization; callers that need
    admission control should authenticate first and/or supply a trusted
    *transaction_setup* callback that registers checks on the transaction and
    raises to reject the change.  Such an exception is propagated after the
    transaction has been rolled back.

    :param update_message: The dynamic update to apply.
    :type update_message: dns.update.UpdateMessage
    :param txn_manager: The transaction manager of the target zone.
    :type txn_manager: dns.transaction.TransactionManager
    :param transaction_setup: Optional callable invoked with the writer
        transaction before any processing, e.g. to install policy checks.
    :raises dns.updater.UpdateError: If any validation, prerequisite or
        update rule fails.  Its ``rcode`` attribute gives the corresponding
        DNS response code.
    :raises TypeError: If *update_message* is not an UpdateMessage.
    """
    if not isinstance(update_message, dns.update.UpdateMessage):
        raise TypeError("update_message must be a dns.update.UpdateMessage")
    origin, zone_class = _validate_zone_section(update_message, txn_manager)
    _, relativize, _ = txn_manager.origin_information()
    # Scope checking is done before any prerequisite evaluation.
    _check_name_scope(update_message, origin)
    with txn_manager.writer() as txn:
        if transaction_setup is not None:
            transaction_setup(txn)
        _check_prerequisites(update_message, txn, origin, relativize)
        _apply_updates(update_message, txn, origin, zone_class, relativize)
