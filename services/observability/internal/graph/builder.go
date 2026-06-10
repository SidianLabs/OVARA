package graph

import (
	"fmt"
	"sort"

	"ovara.services.observability/internal/models"
)

type Builder struct{}

func NewBuilder() *Builder {
	return &Builder{}
}

func (b *Builder) BuildLineage(events []models.TraceEvent) models.TraceGraph {
	if len(events) == 0 {
		return models.TraceGraph{}
	}

	byType := make(map[models.EventType][]models.TraceEvent)
	for _, evt := range events {
		byType[evt.EventType] = append(byType[evt.EventType], evt)
	}

	var nodes []models.TraceNode
	var edges []models.TraceEdge
	seenNodes := make(map[string]bool)

	for _, evt := range events {
		nodeID := fmt.Sprintf("%s:%s", evt.SpanID, evt.EventType)
		if seenNodes[nodeID] {
			continue
		}
		seenNodes[nodeID] = true

		nodeType := eventTypeToNodeType(evt.EventType)
		node := models.TraceNode{
			ID:        nodeID,
			Type:      nodeType,
			Label:     fmt.Sprintf("%s on %s", evt.EventType, evt.Action),
			Timestamp: evt.Timestamp,
			Metadata: map[string]string{
				"trace_id": evt.TraceID,
				"span_id":  evt.SpanID,
				"agent_id": evt.AgentID,
			},
			}
		if evt.TrustScore > 0 {
			node.Metadata["trust_score"] = fmt.Sprintf("%.2f", evt.TrustScore)
		}
		if evt.Decision != "" {
			node.Metadata["decision"] = evt.Decision
		}
		nodes = append(nodes, node)
	}

	eventOrder := []models.EventType{
		models.EventActionRequested,
		models.EventPolicyEvaluated,
		models.EventTrustComputed,
		models.EventApprovalRequested,
		models.EventActionExecuted,
		models.EventReceiptIssued,
		models.EventAnomalyDetected,
	}

	orderedEvents := make([]models.TraceEvent, 0, len(events))
	for _, et := range eventOrder {
		for _, evt := range byType[et] {
			orderedEvents = append(orderedEvents, evt)
		}
	}
	for _, evt := range events {
		added := false
		for _, et := range eventOrder {
			if evt.EventType == et {
				added = true
				break
			}
		}
		if !added {
			orderedEvents = append(orderedEvents, evt)
		}
	}

	edgeSeen := make(map[string]bool)
	for i := 1; i < len(orderedEvents); i++ {
		prev := orderedEvents[i-1]
		curr := orderedEvents[i]
		if prev.TraceID != curr.TraceID {
			continue
		}

		fromID := fmt.Sprintf("%s:%s", prev.SpanID, prev.EventType)
		toID := fmt.Sprintf("%s:%s", curr.SpanID, curr.EventType)
		if fromID == toID {
			continue
		}

		rel := determineRelationship(prev.EventType, curr.EventType)
		edgeKey := fmt.Sprintf("%s->%s:%s", fromID, toID, rel)
		if edgeSeen[edgeKey] {
			continue
		}
		edgeSeen[edgeKey] = true

		edges = append(edges, models.TraceEdge{
			From:         fromID,
			To:           toID,
			Relationship: rel,
		})
	}

	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Timestamp.Before(nodes[j].Timestamp)
	})

	return models.TraceGraph{Nodes: nodes, Edges: edges}
}

func (b *Builder) BuildAgentGraph(agentID string, events []models.TraceEvent) models.TraceGraph {
	var filtered []models.TraceEvent
	for _, evt := range events {
		if evt.AgentID == agentID {
			filtered = append(filtered, evt)
		}
	}
	return b.BuildLineage(filtered)
}

func (b *Builder) DetectCycles(graph models.TraceGraph) [][]string {
	adj := make(map[string][]string)
	for _, edge := range graph.Edges {
		adj[edge.From] = append(adj[edge.From], edge.To)
	}

	var cycles [][]string
	visited := make(map[string]int)
	var path []string
	pathSet := make(map[string]bool)

	var dfs func(string)
	dfs = func(node string) {
		if pathSet[node] {
			cycleStart := -1
			for i, p := range path {
				if p == node {
					cycleStart = i
					break
				}
			}
			if cycleStart >= 0 {
				cycle := make([]string, len(path)-cycleStart)
				copy(cycle, path[cycleStart:])
				cycle = append(cycle, node)
				cycles = append(cycles, cycle)
			}
			return
		}
		if visited[node] == 2 {
			return
		}

		visited[node] = 1
		pathSet[node] = true
		path = append(path, node)

		for _, neighbor := range adj[node] {
			dfs(neighbor)
		}

		path = path[:len(path)-1]
		delete(pathSet, node)
		visited[node] = 2
	}

	for _, node := range graph.Nodes {
		if visited[node.ID] == 0 {
			dfs(node.ID)
		}
	}

	return cycles
}

func (b *Builder) FindCriticalPath(graph models.TraceGraph) []models.TraceNode {
	if len(graph.Nodes) == 0 {
		return []models.TraceNode{}
	}

	adj := make(map[string][]models.TraceEdge)
	inDeg := make(map[string]int)
	for _, node := range graph.Nodes {
		inDeg[node.ID] = 0
	}
	for _, edge := range graph.Edges {
		adj[edge.From] = append(adj[edge.From], edge)
		inDeg[edge.To]++
	}

	nodeMap := make(map[string]models.TraceNode)
	for _, node := range graph.Nodes {
		nodeMap[node.ID] = node
	}

	var queue []string
	dist := make(map[string]int)
	prev := make(map[string]string)

	for id, deg := range inDeg {
		if deg == 0 {
			queue = append(queue, id)
			dist[id] = 0
		}
	}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		for _, edge := range adj[curr] {
			inDeg[edge.To]--
			newDist := dist[curr] + 1
			if d, ok := dist[edge.To]; !ok || newDist > d {
				dist[edge.To] = newDist
				prev[edge.To] = curr
			}
			if inDeg[edge.To] == 0 {
				queue = append(queue, edge.To)
			}
		}
	}

	farthest := ""
	maxDist := -1
	for id, d := range dist {
		if d > maxDist {
			maxDist = d
			farthest = id
		}
	}

	if farthest == "" {
		if len(graph.Nodes) > 0 {
			return []models.TraceNode{graph.Nodes[0]}
		}
		return []models.TraceNode{}
	}

	var path []string
	for n := farthest; n != ""; n = prev[n] {
		path = append(path, n)
	}

	result := make([]models.TraceNode, 0, len(path))
	for i := len(path) - 1; i >= 0; i-- {
		if node, ok := nodeMap[path[i]]; ok {
			result = append(result, node)
		}
	}

	return result
}

func (b *Builder) MergeGraphs(graphs []models.TraceGraph) models.TraceGraph {
	seenNodes := make(map[string]bool)
	seenEdges := make(map[string]bool)
	var nodes []models.TraceNode
	var edges []models.TraceEdge

	for _, g := range graphs {
		for _, node := range g.Nodes {
			if !seenNodes[node.ID] {
				seenNodes[node.ID] = true
				nodes = append(nodes, node)
			}
		}
		for _, edge := range g.Edges {
			key := fmt.Sprintf("%s->%s:%s", edge.From, edge.To, edge.Relationship)
			if !seenEdges[key] {
				seenEdges[key] = true
				edges = append(edges, edge)
			}
		}
	}

	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Timestamp.Before(nodes[j].Timestamp)
	})

	return models.TraceGraph{Nodes: nodes, Edges: edges}
}

func eventTypeToNodeType(et models.EventType) models.NodeType {
	switch et {
	case models.EventActionRequested:
		return models.NodeTypeAction
	case models.EventPolicyEvaluated:
		return models.NodeTypePolicy
	case models.EventTrustComputed:
		return models.NodeTypeTrust
	case models.EventApprovalRequested:
		return models.NodeTypeApproval
	case models.EventActionExecuted:
		return models.NodeTypeExecution
	case models.EventReceiptIssued:
		return models.NodeTypeReceipt
	default:
		return models.NodeTypeAction
	}
}

func determineRelationship(from, to models.EventType) models.EdgeRelationship {
	switch {
	case from == models.EventActionRequested && to == models.EventPolicyEvaluated:
		return models.RelTriggeredBy
	case from == models.EventPolicyEvaluated && to == models.EventTrustComputed:
		return models.RelDecidedBy
	case from == models.EventTrustComputed && to == models.EventApprovalRequested:
		return models.RelTriggeredBy
	case from == models.EventApprovalRequested && to == models.EventActionExecuted:
		return models.RelApprovedBy
	case from == models.EventActionExecuted && to == models.EventReceiptIssued:
		return models.RelProduced
	case to == models.EventAnomalyDetected:
		return models.RelTriggeredBy
	default:
		return models.RelTriggeredBy
	}
}
