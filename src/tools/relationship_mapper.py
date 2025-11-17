"""
Relationship Mapper for mapping relationships between security entities.

This module provides relationship mapping capabilities for:
- Control→Risk mappings (what controls mitigate what risks)
- Asset→Vulnerability mappings
- CVE→Asset mappings
- Control→Asset mappings (what controls protect what assets)
- Graph-based relationship storage using NetworkX
- Path finding between entities
- Relationship inference from text
"""

import logging
import json
from typing import Dict, List, Tuple, Optional, Any, Set
from pathlib import Path
from collections import defaultdict

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    nx = None

from src.tools.entity_extractor import EntityExtractor

logger = logging.getLogger(__name__)


class RelationshipMapper:
    """
    Enterprise-grade relationship mapper for security entities.

    Features:
    - Directed graph-based relationship storage
    - Multiple relationship types
    - Entity metadata storage
    - Relationship confidence scoring
    - Path finding between entities
    - Automatic relationship inference from text
    - JSON export/import for persistence
    - Integration with EntityExtractor
    """

    # Supported relationship types
    RELATIONSHIP_TYPES = {
        'mitigates': 'Control mitigates risk',
        'protects': 'Control protects asset',
        'affects': 'Vulnerability affects asset',
        'exploits': 'CVE exploits vulnerability',
        'implements': 'Asset implements control',
        'depends_on': 'Entity depends on another entity',
        'related_to': 'Generic relationship',
    }

    # Entity type mappings
    ENTITY_TYPES = {
        'control', 'risk', 'asset', 'vulnerability', 'cve',
        'framework', 'threat', 'impact', 'mitigation'
    }

    MIN_CONFIDENCE = 0.3
    HIGH_CONFIDENCE = 0.8

    def __init__(self, use_entity_extractor: bool = True):
        """
        Initialize relationship mapper.

        Args:
            use_entity_extractor: Whether to use EntityExtractor for entity discovery
        """
        self.graph = None
        self.entity_extractor = None
        self.relationship_count = 0
        self.entity_count = 0

        # Initialize NetworkX graph
        self._init_graph()

        # Initialize entity extractor if requested
        if use_entity_extractor:
            try:
                self.entity_extractor = EntityExtractor()
                logger.info("EntityExtractor initialized for relationship mapping")
            except Exception as e:
                logger.warning(f"Could not initialize EntityExtractor: {e}")

    def _init_graph(self):
        """Initialize NetworkX directed graph."""
        if not NETWORKX_AVAILABLE:
            logger.warning("NetworkX not available, relationship mapping disabled")
            self.graph = None
            return

        try:
            # Validate NetworkX API
            if not hasattr(nx, 'DiGraph'):
                logger.warning("NetworkX API incompatible")
                self.graph = None
                return

            self.graph = nx.DiGraph()
            logger.info("NetworkX DiGraph initialized")

        except Exception as e:
            logger.error(f"Error initializing NetworkX graph: {e}")
            self.graph = None

    def add_entity(
        self,
        entity_id: str,
        entity_type: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Add entity node to graph.

        Args:
            entity_id: Unique identifier for entity
            entity_type: Type of entity (control, risk, asset, etc.)
            metadata: Additional entity metadata

        Returns:
            True if entity was added successfully
        """
        if self.graph is None:
            logger.error("Graph not initialized")
            return False

        try:
            if not entity_id or not isinstance(entity_id, str):
                logger.error("Invalid entity_id")
                return False

            # Prepare node attributes
            node_attrs = {
                'type': entity_type,
                'metadata': metadata or {}
            }

            # Add or update node
            self.graph.add_node(entity_id, **node_attrs)
            self.entity_count = self.graph.number_of_nodes()

            logger.debug(f"Added entity: {entity_id} (type: {entity_type})")
            return True

        except Exception as e:
            logger.error(f"Error adding entity: {e}")
            return False

    def add_relationship(
        self,
        source: str,
        target: str,
        rel_type: str,
        confidence: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Add relationship edge to graph.

        Args:
            source: Source entity ID
            target: Target entity ID
            rel_type: Relationship type
            confidence: Confidence score (0.0-1.0)
            metadata: Additional relationship metadata

        Returns:
            True if relationship was added successfully
        """
        if self.graph is None:
            logger.error("Graph not initialized")
            return False

        try:
            if not source or not target:
                logger.error("Invalid source or target")
                return False

            # Validate confidence
            confidence = max(0.0, min(1.0, confidence))

            # Prepare edge attributes
            edge_attrs = {
                'type': rel_type,
                'confidence': confidence,
                'metadata': metadata or {}
            }

            # Add edge (automatically adds nodes if they don't exist)
            self.graph.add_edge(source, target, **edge_attrs)
            self.relationship_count = self.graph.number_of_edges()

            logger.debug(
                f"Added relationship: {source} --[{rel_type}]--> {target} "
                f"(confidence: {confidence:.2f})"
            )
            return True

        except Exception as e:
            logger.error(f"Error adding relationship: {e}")
            return False

    def map_control_to_risk(
        self,
        control: str,
        risk: str,
        confidence: float = 1.0
    ) -> bool:
        """
        Map control to risk (control mitigates risk).

        Args:
            control: Control identifier
            risk: Risk identifier
            confidence: Confidence score

        Returns:
            True if mapping was successful
        """
        try:
            # Add entities
            self.add_entity(control, 'control')
            self.add_entity(risk, 'risk')

            # Add relationship
            return self.add_relationship(
                control,
                risk,
                'mitigates',
                confidence=confidence,
                metadata={'relationship_type': 'control_to_risk'}
            )

        except Exception as e:
            logger.error(f"Error mapping control to risk: {e}")
            return False

    def map_asset_to_vulnerability(
        self,
        asset: str,
        vulnerability: str,
        confidence: float = 1.0
    ) -> bool:
        """
        Map asset to vulnerability.

        Args:
            asset: Asset identifier
            vulnerability: Vulnerability identifier
            confidence: Confidence score

        Returns:
            True if mapping was successful
        """
        try:
            # Add entities
            self.add_entity(asset, 'asset')
            self.add_entity(vulnerability, 'vulnerability')

            # Add relationship
            return self.add_relationship(
                vulnerability,
                asset,
                'affects',
                confidence=confidence,
                metadata={'relationship_type': 'vulnerability_to_asset'}
            )

        except Exception as e:
            logger.error(f"Error mapping asset to vulnerability: {e}")
            return False

    def map_cve_to_asset(
        self,
        cve: str,
        asset: str,
        confidence: float = 1.0
    ) -> bool:
        """
        Map CVE to asset.

        Args:
            cve: CVE identifier
            asset: Asset identifier
            confidence: Confidence score

        Returns:
            True if mapping was successful
        """
        try:
            # Add entities
            self.add_entity(cve, 'cve')
            self.add_entity(asset, 'asset')

            # Add relationship
            return self.add_relationship(
                cve,
                asset,
                'affects',
                confidence=confidence,
                metadata={'relationship_type': 'cve_to_asset'}
            )

        except Exception as e:
            logger.error(f"Error mapping CVE to asset: {e}")
            return False

    def map_control_to_asset(
        self,
        control: str,
        asset: str,
        confidence: float = 1.0
    ) -> bool:
        """
        Map control to asset (control protects asset).

        Args:
            control: Control identifier
            asset: Asset identifier
            confidence: Confidence score

        Returns:
            True if mapping was successful
        """
        try:
            # Add entities
            self.add_entity(control, 'control')
            self.add_entity(asset, 'asset')

            # Add relationship
            return self.add_relationship(
                control,
                asset,
                'protects',
                confidence=confidence,
                metadata={'relationship_type': 'control_to_asset'}
            )

        except Exception as e:
            logger.error(f"Error mapping control to asset: {e}")
            return False

    def get_relationships(self, entity_id: str) -> List[Dict[str, Any]]:
        """
        Get all relationships for an entity.

        Args:
            entity_id: Entity identifier

        Returns:
            List of relationship dictionaries
        """
        if self.graph is None:
            return []

        try:
            if entity_id not in self.graph:
                return []

            relationships = []

            # Get outgoing edges
            for target in self.graph.successors(entity_id):
                edge_data = self.graph[entity_id][target]
                relationships.append({
                    'source': entity_id,
                    'target': target,
                    'type': edge_data.get('type', 'unknown'),
                    'confidence': edge_data.get('confidence', 1.0),
                    'metadata': edge_data.get('metadata', {}),
                    'direction': 'outgoing'
                })

            # Get incoming edges
            for source in self.graph.predecessors(entity_id):
                edge_data = self.graph[source][entity_id]
                relationships.append({
                    'source': source,
                    'target': entity_id,
                    'type': edge_data.get('type', 'unknown'),
                    'confidence': edge_data.get('confidence', 1.0),
                    'metadata': edge_data.get('metadata', {}),
                    'direction': 'incoming'
                })

            return relationships

        except Exception as e:
            logger.error(f"Error getting relationships: {e}")
            return []

    def get_related_entities(
        self,
        entity_id: str,
        rel_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get entities connected to given entity.

        Args:
            entity_id: Entity identifier
            rel_type: Filter by relationship type (optional)

        Returns:
            List of related entity dictionaries
        """
        if self.graph is None:
            return []

        try:
            if entity_id not in self.graph:
                return []

            related = []

            # Get outgoing connections
            for target in self.graph.successors(entity_id):
                edge_data = self.graph[entity_id][target]
                if rel_type is None or edge_data.get('type') == rel_type:
                    node_data = self.graph.nodes[target]
                    related.append({
                        'entity_id': target,
                        'entity_type': node_data.get('type', 'unknown'),
                        'relationship_type': edge_data.get('type', 'unknown'),
                        'confidence': edge_data.get('confidence', 1.0),
                        'direction': 'outgoing'
                    })

            # Get incoming connections
            for source in self.graph.predecessors(entity_id):
                edge_data = self.graph[source][entity_id]
                if rel_type is None or edge_data.get('type') == rel_type:
                    node_data = self.graph.nodes[source]
                    related.append({
                        'entity_id': source,
                        'entity_type': node_data.get('type', 'unknown'),
                        'relationship_type': edge_data.get('type', 'unknown'),
                        'confidence': edge_data.get('confidence', 1.0),
                        'direction': 'incoming'
                    })

            return related

        except Exception as e:
            logger.error(f"Error getting related entities: {e}")
            return []

    def find_paths(
        self,
        source: str,
        target: str,
        max_length: int = 3
    ) -> List[List[str]]:
        """
        Find paths between two entities.

        Args:
            source: Source entity ID
            target: Target entity ID
            max_length: Maximum path length

        Returns:
            List of paths (each path is a list of entity IDs)
        """
        if self.graph is None:
            return []

        try:
            if source not in self.graph or target not in self.graph:
                return []

            # Find all simple paths up to max_length
            paths = []
            for path in nx.all_simple_paths(
                self.graph,
                source,
                target,
                cutoff=max_length
            ):
                paths.append(path)

            return paths

        except Exception as e:
            logger.error(f"Error finding paths: {e}")
            return []

    def extract_and_map_from_text(self, text: str) -> Dict[str, Any]:
        """
        Extract entities from text and infer relationships.

        Args:
            text: Text to analyze

        Returns:
            Dictionary with extracted entities and inferred relationships
        """
        if not self.entity_extractor:
            logger.warning("EntityExtractor not available")
            return {'entities': [], 'relationships': []}

        try:
            # Extract entities
            extracted = self.entity_extractor.extract_entities(text)

            entities_added = []
            relationships_added = []

            # Process CVEs
            for cve in extracted.get('cves', []):
                entity_id = cve['value']
                self.add_entity(
                    entity_id,
                    'cve',
                    metadata={'confidence': cve['confidence'], 'context': cve.get('context', '')}
                )
                entities_added.append({'id': entity_id, 'type': 'cve'})

            # Process controls
            for control in extracted.get('controls', []):
                entity_id = control['value']
                control_type = control.get('type', 'control')
                self.add_entity(
                    entity_id,
                    'control',
                    metadata={
                        'confidence': control['confidence'],
                        'framework': control_type,
                        'context': control.get('context', '')
                    }
                )
                entities_added.append({'id': entity_id, 'type': 'control'})

            # Process assets
            for asset in extracted.get('assets', []):
                entity_id = asset['value']
                asset_type = asset.get('type', 'asset')
                self.add_entity(
                    entity_id,
                    'asset',
                    metadata={
                        'confidence': asset['confidence'],
                        'asset_type': asset_type,
                        'context': asset.get('context', '')
                    }
                )
                entities_added.append({'id': entity_id, 'type': 'asset'})

            # Process risks
            for risk in extracted.get('risks', []):
                entity_id = risk['value']
                risk_type = risk.get('type', 'risk')
                self.add_entity(
                    entity_id,
                    risk_type,
                    metadata={'confidence': risk['confidence'], 'context': risk.get('context', '')}
                )
                entities_added.append({'id': entity_id, 'type': risk_type})

            # Infer relationships based on co-occurrence
            relationships_added = self._infer_relationships_from_entities(
                extracted,
                text
            )

            return {
                'entities': entities_added,
                'relationships': relationships_added,
                'summary': {
                    'entities_added': len(entities_added),
                    'relationships_added': len(relationships_added)
                }
            }

        except Exception as e:
            logger.error(f"Error extracting and mapping from text: {e}")
            return {'entities': [], 'relationships': []}

    def _infer_relationships_from_entities(
        self,
        extracted: Dict[str, Any],
        text: str
    ) -> List[Dict[str, Any]]:
        """
        Infer relationships based on entity co-occurrence.

        Args:
            extracted: Extracted entities from EntityExtractor
            text: Original text

        Returns:
            List of inferred relationships
        """
        relationships = []

        try:
            cves = extracted.get('cves', [])
            controls = extracted.get('controls', [])
            assets = extracted.get('assets', [])
            risks = extracted.get('risks', [])

            # Split text into sentences for context analysis
            sentences = text.split('.')

            for sentence in sentences:
                sentence_lower = sentence.lower()

                # Infer CVE → Asset relationships
                for cve in cves:
                    if cve['value'] in sentence:
                        for asset in assets:
                            if asset['value'].lower() in sentence_lower:
                                confidence = min(cve['confidence'], asset['confidence']) * 0.8
                                if self.map_cve_to_asset(cve['value'], asset['value'], confidence):
                                    relationships.append({
                                        'source': cve['value'],
                                        'target': asset['value'],
                                        'type': 'affects',
                                        'confidence': confidence,
                                        'inferred': True
                                    })

                # Infer Control → Risk relationships
                for control in controls:
                    if control['value'] in sentence:
                        for risk in risks:
                            if risk['value'].lower() in sentence_lower:
                                confidence = min(control['confidence'], risk['confidence']) * 0.7
                                if self.map_control_to_risk(control['value'], risk['value'], confidence):
                                    relationships.append({
                                        'source': control['value'],
                                        'target': risk['value'],
                                        'type': 'mitigates',
                                        'confidence': confidence,
                                        'inferred': True
                                    })

                # Infer Control → Asset relationships
                for control in controls:
                    if control['value'] in sentence:
                        for asset in assets:
                            if asset['value'].lower() in sentence_lower:
                                confidence = min(control['confidence'], asset['confidence']) * 0.7
                                if self.map_control_to_asset(control['value'], asset['value'], confidence):
                                    relationships.append({
                                        'source': control['value'],
                                        'target': asset['value'],
                                        'type': 'protects',
                                        'confidence': confidence,
                                        'inferred': True
                                    })

        except Exception as e:
            logger.error(f"Error inferring relationships: {e}")

        return relationships

    def export_to_json(self, filepath: str) -> bool:
        """
        Export graph to JSON file.

        Args:
            filepath: Path to export file

        Returns:
            True if export was successful
        """
        if self.graph is None:
            logger.error("Graph not initialized")
            return False

        try:
            # Prepare graph data
            graph_data = {
                'nodes': [],
                'edges': [],
                'metadata': {
                    'entity_count': self.graph.number_of_nodes(),
                    'relationship_count': self.graph.number_of_edges()
                }
            }

            # Export nodes
            for node_id in self.graph.nodes():
                node_data = self.graph.nodes[node_id]
                graph_data['nodes'].append({
                    'id': node_id,
                    'type': node_data.get('type', 'unknown'),
                    'metadata': node_data.get('metadata', {})
                })

            # Export edges
            for source, target in self.graph.edges():
                edge_data = self.graph[source][target]
                graph_data['edges'].append({
                    'source': source,
                    'target': target,
                    'type': edge_data.get('type', 'unknown'),
                    'confidence': edge_data.get('confidence', 1.0),
                    'metadata': edge_data.get('metadata', {})
                })

            # Write to file
            filepath = Path(filepath)
            filepath.parent.mkdir(parents=True, exist_ok=True)

            with open(filepath, 'w') as f:
                json.dump(graph_data, f, indent=2)

            logger.info(f"Graph exported to {filepath}")
            return True

        except Exception as e:
            logger.error(f"Error exporting graph: {e}")
            return False

    def import_from_json(self, filepath: str) -> bool:
        """
        Import graph from JSON file.

        Args:
            filepath: Path to import file

        Returns:
            True if import was successful
        """
        if self.graph is None:
            logger.error("Graph not initialized")
            return False

        try:
            filepath = Path(filepath)

            if not filepath.exists():
                logger.error(f"File not found: {filepath}")
                return False

            with open(filepath, 'r') as f:
                graph_data = json.load(f)

            # Clear existing graph
            self.graph.clear()

            # Import nodes
            for node in graph_data.get('nodes', []):
                self.add_entity(
                    node['id'],
                    node.get('type', 'unknown'),
                    metadata=node.get('metadata', {})
                )

            # Import edges
            for edge in graph_data.get('edges', []):
                self.add_relationship(
                    edge['source'],
                    edge['target'],
                    edge.get('type', 'related_to'),
                    confidence=edge.get('confidence', 1.0),
                    metadata=edge.get('metadata', {})
                )

            logger.info(f"Graph imported from {filepath}")
            return True

        except Exception as e:
            logger.error(f"Error importing graph: {e}")
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get graph statistics.

        Returns:
            Dictionary with graph statistics
        """
        if not self.graph:
            return {
                'networkx_available': NETWORKX_AVAILABLE,
                'graph_initialized': False,
                'entity_count': 0,
                'relationship_count': 0
            }

        try:
            # Count entities by type
            entity_types = defaultdict(int)
            for node_id in self.graph.nodes():
                node_type = self.graph.nodes[node_id].get('type', 'unknown')
                entity_types[node_type] += 1

            # Count relationships by type
            relationship_types = defaultdict(int)
            for source, target in self.graph.edges():
                rel_type = self.graph[source][target].get('type', 'unknown')
                relationship_types[rel_type] += 1

            return {
                'networkx_available': NETWORKX_AVAILABLE,
                'graph_initialized': True,
                'entity_count': self.graph.number_of_nodes(),
                'relationship_count': self.graph.number_of_edges(),
                'entity_types': dict(entity_types),
                'relationship_types': dict(relationship_types),
                'supported_relationship_types': list(self.RELATIONSHIP_TYPES.keys()),
                'entity_extractor_available': self.entity_extractor is not None
            }

        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}

    def visualize_graph(self) -> Dict[str, Any]:
        """
        Get graph visualization data.

        Returns:
            Dictionary with nodes and edges for visualization
        """
        if not self.graph:
            return {'nodes': [], 'edges': []}

        try:
            nodes = []
            edges = []

            # Get nodes
            for node_id in self.graph.nodes():
                node_data = self.graph.nodes[node_id]
                nodes.append({
                    'id': node_id,
                    'type': node_data.get('type', 'unknown'),
                    'label': node_id
                })

            # Get edges
            for source, target in self.graph.edges():
                edge_data = self.graph[source][target]
                edges.append({
                    'source': source,
                    'target': target,
                    'type': edge_data.get('type', 'unknown'),
                    'confidence': edge_data.get('confidence', 1.0),
                    'label': edge_data.get('type', 'unknown')
                })

            return {
                'nodes': nodes,
                'edges': edges,
                'summary': {
                    'node_count': len(nodes),
                    'edge_count': len(edges)
                }
            }

        except Exception as e:
            logger.error(f"Error visualizing graph: {e}")
            return {'nodes': [], 'edges': []}
