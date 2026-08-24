"""Mission-native trace identity. The Mission mints the root; identity flows only downward; ids are
content-addressed (replay-stable); a substrate can only nest under a Mission node, never become the root."""
from types import SimpleNamespace

from runtime_contracts import TraceContext, span_of


def test_mission_roots_the_trace_and_children_keep_the_trace_id():
    root = TraceContext.root("m-7F21", intent_id="deploy-svc")
    node = root.child(node_id="n-deploy")
    cap = node.child(capability="k8s.apply")
    # one trace_id all the way down
    assert node.trace_id == root.trace_id == cap.trace_id
    # each span parents to its cause
    assert node.parent_span_id == root.span_id
    assert cap.parent_span_id == node.span_id
    # semantic refs propagate
    assert cap.mission_id == "m-7F21" and cap.intent_id == "deploy-svc" and cap.capability == "k8s.apply"


def test_ids_are_content_addressed_and_replay_stable():
    a = TraceContext.root("m-7F21").child(node_id="n1", capability="k8s.apply")
    b = TraceContext.root("m-7F21").child(node_id="n1", capability="k8s.apply")
    assert a.trace_id == b.trace_id and a.span_id == b.span_id       # same mission+path → same trace
    c = TraceContext.root("m-OTHER").child(node_id="n1", capability="k8s.apply")
    assert c.trace_id != a.trace_id                                  # different mission → different trace


def test_traceparent_roundtrips_and_substrate_nests_under_node():
    node = TraceContext.root("m1").child(node_id="deploy")
    tp = node.traceparent()
    assert tp.startswith("00-") and tp.count("-") == 3
    # a substrate (Argo) receiving our traceparent continues the SAME trace, parented under our node
    received = TraceContext.parse_traceparent(tp, mission_id="m1", node_id="deploy")
    argo_controller = received.child(step="controller-reconcile")
    assert argo_controller.trace_id == node.trace_id                # same tree
    assert argo_controller.parent_span_id == node.span_id           # nested UNDER the mission node
    # the substrate never becomes the root: its trace_id is the Mission's, not a fresh one
    assert argo_controller.trace_id == TraceContext.root("m1").trace_id


def test_baggage_carries_mission_semantics():
    ctx = TraceContext.root("m1", intent_id="i9").child(node_id="n2", capability="terraform.apply")
    bag = ctx.baggage()
    assert bag["redevops.mission_id"] == "m1"
    assert bag["redevops.node_id"] == "n2"
    assert bag["redevops.capability"] == "terraform.apply"
    assert bag["redevops.intent_id"] == "i9"


def test_span_projection_carries_refs_not_payloads():
    ctx = TraceContext.root("m1").child(node_id="n", capability="storage.upload")
    ev = SimpleNamespace(event_id="e1", event_type="network_access", kind=SimpleNamespace(value="EXECUTION"),
                         capability="storage.upload", network=("s3.external.com",),
                         data_classifications=("pii",), permissions_exercised=("write:storage",),
                         authority_chain_ref="m1@rcv1:abc", result="ok")
    span = span_of(ev, ctx)
    assert span["trace_id"] == ctx.trace_id and span["parent_span_id"] == ctx.parent_span_id
    assert span["status"] == "OK" and span["name"] == "storage.upload"
    assert span["attributes"]["redevops.network"] == ["s3.external.com"]
    assert span["attributes"]["redevops.authority_chain_ref"] == "m1@rcv1:abc"
    # error result flips the span status
    ev_err = SimpleNamespace(event_id="e2", event_type="x", kind=SimpleNamespace(value="SECURITY"),
                             capability="c", result="error")
    assert span_of(ev_err, ctx)["status"] == "ERROR"
