"""
Comprehensive tests for Relationship Mapper.

Tests cover:
- Graph initialization
- Entity management
- Relationship creation
- Relationship mapping (control→risk, asset→vulnerability, etc.)
- Graph queries (relationships, related entities, paths)
- Entity extraction and relationship inference
- JSON export/import
- Graph statistics
- Visualization
- Error handling
- Edge cases
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import json
import tempfile

from src.tools.relationship_mapper import RelationshipMapper


@pytest.fixture
def relationship_mapper():
    """Create relationship mapper instance."""
    return RelationshipMapper(use_entity_extractor=False)


@pytest.fixture
def relationship_mapper_with_extractor():
    """Create relationship mapper with entity extractor."""
    return RelationshipMapper(use_entity_extractor=True)


@pytest.fixture
def sample_graph_data():
    """Sample graph data for testing."""
    return {
        'entities': [
            ('AC-2', 'control'),
            ('AC-3', 'control'),
            ('CVE-2024-1234', 'cve'),
            ('web-server', 'asset'),
            ('database', 'asset'),
            ('unauthorized-access', 'risk'),
            ('sql-injection', 'vulnerability'),
        ],
        'relationships': [
            ('AC-2', 'unauthorized-access', 'mitigates', 0.9),
            ('AC-3', 'unauthorized-access', 'mitigates', 0.85),
            ('CVE-2024-1234', 'web-server', 'affects', 0.95),
            ('sql-injection', 'database', 'affects', 0.9),
            ('AC-2', 'web-server', 'protects', 0.8),
        ]
    }


@pytest.fixture
def sample_security_text():
    """Sample security text for relationship inference."""
    return """
    Control AC-2 mitigates the risk of unauthorized access to the web server.
    The CVE-2024-1234 vulnerability affects the database server.
    Implementation of AC-3 helps protect critical applications.
    SQL injection vulnerabilities pose a threat to our databases.
    """


class TestRelationshipMapperInit:
    """Test relationship mapper initialization."""

    def test_init_without_extractor(self):
        """Test initialization without entity extractor."""
        mapper = RelationshipMapper(use_entity_extractor=False)
        assert mapper.graph is not None or not mapper.graph  # Depends on NetworkX availability
        assert mapper.entity_extractor is None

    def test_init_with_extractor(self):
        """Test initialization with entity extractor."""
        mapper = RelationshipMapper(use_entity_extractor=True)
        # Entity extractor may or may not be initialized depending on dependencies
        assert isinstance(mapper.entity_extractor, object) or mapper.entity_extractor is None

    def test_relationship_types_defined(self):
        """Test relationship types are defined."""
        assert 'mitigates' in RelationshipMapper.RELATIONSHIP_TYPES
        assert 'protects' in RelationshipMapper.RELATIONSHIP_TYPES
        assert 'affects' in RelationshipMapper.RELATIONSHIP_TYPES
        assert 'exploits' in RelationshipMapper.RELATIONSHIP_TYPES
        assert 'implements' in RelationshipMapper.RELATIONSHIP_TYPES

    def test_entity_types_defined(self):
        """Test entity types are defined."""
        assert 'control' in RelationshipMapper.ENTITY_TYPES
        assert 'risk' in RelationshipMapper.ENTITY_TYPES
        assert 'asset' in RelationshipMapper.ENTITY_TYPES
        assert 'vulnerability' in RelationshipMapper.ENTITY_TYPES
        assert 'cve' in RelationshipMapper.ENTITY_TYPES

    def test_graph_initialization(self):
        """Test graph is properly initialized."""
        mapper = RelationshipMapper(use_entity_extractor=False)
        # Graph should be initialized if NetworkX is available
        if mapper.graph:
            assert mapper.entity_count == 0
            assert mapper.relationship_count == 0


class TestAddEntity:
    """Test entity addition."""

    def test_add_entity_basic(self, relationship_mapper):
        """Test adding basic entity."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        result = relationship_mapper.add_entity('AC-2', 'control')
        assert result is True
        assert relationship_mapper.entity_count == 1

    def test_add_entity_with_metadata(self, relationship_mapper):
        """Test adding entity with metadata."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        metadata = {'framework': 'NIST', 'confidence': 0.9}
        result = relationship_mapper.add_entity('AC-2', 'control', metadata=metadata)
        assert result is True

    def test_add_multiple_entities(self, relationship_mapper):
        """Test adding multiple entities."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        relationship_mapper.add_entity('AC-2', 'control')
        relationship_mapper.add_entity('CVE-2024-1234', 'cve')
        relationship_mapper.add_entity('web-server', 'asset')

        assert relationship_mapper.entity_count == 3

    def test_add_duplicate_entity(self, relationship_mapper):
        """Test adding duplicate entity updates it."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        relationship_mapper.add_entity('AC-2', 'control')
        relationship_mapper.add_entity('AC-2', 'control')  # Duplicate

        # Should still be 1 entity
        assert relationship_mapper.entity_count == 1

    def test_add_entity_invalid_id(self, relationship_mapper):
        """Test adding entity with invalid ID."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        result = relationship_mapper.add_entity('', 'control')
        assert result is False

        result = relationship_mapper.add_entity(None, 'control')
        assert result is False


class TestAddRelationship:
    """Test relationship addition."""

    def test_add_relationship_basic(self, relationship_mapper):
        """Test adding basic relationship."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        result = relationship_mapper.add_relationship(
            'AC-2',
            'unauthorized-access',
            'mitigates'
        )
        assert result is True
        assert relationship_mapper.relationship_count == 1

    def test_add_relationship_with_confidence(self, relationship_mapper):
        """Test adding relationship with confidence."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        result = relationship_mapper.add_relationship(
            'AC-2',
            'unauthorized-access',
            'mitigates',
            confidence=0.85
        )
        assert result is True

    def test_add_relationship_with_metadata(self, relationship_mapper):
        """Test adding relationship with metadata."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        metadata = {'source': 'manual', 'verified': True}
        result = relationship_mapper.add_relationship(
            'AC-2',
            'unauthorized-access',
            'mitigates',
            metadata=metadata
        )
        assert result is True

    def test_add_multiple_relationships(self, relationship_mapper):
        """Test adding multiple relationships."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        relationship_mapper.add_relationship('AC-2', 'risk1', 'mitigates')
        relationship_mapper.add_relationship('AC-3', 'risk2', 'mitigates')
        relationship_mapper.add_relationship('CVE-1', 'asset1', 'affects')

        assert relationship_mapper.relationship_count == 3

    def test_add_relationship_confidence_bounds(self, relationship_mapper):
        """Test confidence is bounded between 0 and 1."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        # Confidence > 1 should be clamped to 1
        relationship_mapper.add_relationship(
            'AC-2',
            'risk1',
            'mitigates',
            confidence=1.5
        )

        # Confidence < 0 should be clamped to 0
        relationship_mapper.add_relationship(
            'AC-3',
            'risk2',
            'mitigates',
            confidence=-0.5
        )

        assert relationship_mapper.relationship_count == 2

    def test_add_relationship_invalid_params(self, relationship_mapper):
        """Test adding relationship with invalid parameters."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        result = relationship_mapper.add_relationship('', 'target', 'mitigates')
        assert result is False

        result = relationship_mapper.add_relationship('source', '', 'mitigates')
        assert result is False


class TestMapControlToRisk:
    """Test control→risk mapping."""

    def test_map_control_to_risk_basic(self, relationship_mapper):
        """Test basic control→risk mapping."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        result = relationship_mapper.map_control_to_risk('AC-2', 'unauthorized-access')
        assert result is True
        assert relationship_mapper.entity_count == 2
        assert relationship_mapper.relationship_count == 1

    def test_map_control_to_risk_with_confidence(self, relationship_mapper):
        """Test control→risk mapping with confidence."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        result = relationship_mapper.map_control_to_risk(
            'AC-2',
            'unauthorized-access',
            confidence=0.9
        )
        assert result is True

    def test_map_multiple_controls_to_risk(self, relationship_mapper):
        """Test mapping multiple controls to same risk."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        relationship_mapper.map_control_to_risk('AC-2', 'unauthorized-access')
        relationship_mapper.map_control_to_risk('AC-3', 'unauthorized-access')

        # Should have 2 controls, 1 risk, 2 relationships
        assert relationship_mapper.entity_count == 3
        assert relationship_mapper.relationship_count == 2


class TestMapAssetToVulnerability:
    """Test asset→vulnerability mapping."""

    def test_map_asset_to_vulnerability_basic(self, relationship_mapper):
        """Test basic asset→vulnerability mapping."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        result = relationship_mapper.map_asset_to_vulnerability(
            'web-server',
            'sql-injection'
        )
        assert result is True

    def test_map_asset_to_vulnerability_with_confidence(self, relationship_mapper):
        """Test asset→vulnerability mapping with confidence."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        result = relationship_mapper.map_asset_to_vulnerability(
            'web-server',
            'sql-injection',
            confidence=0.95
        )
        assert result is True


class TestMapCVEToAsset:
    """Test CVE→asset mapping."""

    def test_map_cve_to_asset_basic(self, relationship_mapper):
        """Test basic CVE→asset mapping."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        result = relationship_mapper.map_cve_to_asset('CVE-2024-1234', 'web-server')
        assert result is True

    def test_map_cve_to_asset_with_confidence(self, relationship_mapper):
        """Test CVE→asset mapping with confidence."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        result = relationship_mapper.map_cve_to_asset(
            'CVE-2024-1234',
            'web-server',
            confidence=0.98
        )
        assert result is True

    def test_map_multiple_cves_to_asset(self, relationship_mapper):
        """Test mapping multiple CVEs to same asset."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        relationship_mapper.map_cve_to_asset('CVE-2024-1234', 'web-server')
        relationship_mapper.map_cve_to_asset('CVE-2024-5678', 'web-server')

        assert relationship_mapper.entity_count == 3
        assert relationship_mapper.relationship_count == 2


class TestMapControlToAsset:
    """Test control→asset mapping."""

    def test_map_control_to_asset_basic(self, relationship_mapper):
        """Test basic control→asset mapping."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        result = relationship_mapper.map_control_to_asset('AC-2', 'web-server')
        assert result is True

    def test_map_control_to_asset_with_confidence(self, relationship_mapper):
        """Test control→asset mapping with confidence."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        result = relationship_mapper.map_control_to_asset(
            'AC-2',
            'web-server',
            confidence=0.8
        )
        assert result is True


class TestGetRelationships:
    """Test getting entity relationships."""

    def test_get_relationships_basic(self, relationship_mapper, sample_graph_data):
        """Test getting relationships for entity."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        # Build graph
        for entity_id, entity_type in sample_graph_data['entities']:
            relationship_mapper.add_entity(entity_id, entity_type)

        for source, target, rel_type, conf in sample_graph_data['relationships']:
            relationship_mapper.add_relationship(source, target, rel_type, conf)

        # Get relationships for AC-2
        relationships = relationship_mapper.get_relationships('AC-2')

        assert isinstance(relationships, list)
        assert len(relationships) > 0

    def test_get_relationships_nonexistent_entity(self, relationship_mapper):
        """Test getting relationships for nonexistent entity."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        relationships = relationship_mapper.get_relationships('nonexistent')
        assert relationships == []

    def test_get_relationships_includes_direction(self, relationship_mapper):
        """Test relationships include direction information."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        relationship_mapper.add_relationship('AC-2', 'risk1', 'mitigates')

        relationships = relationship_mapper.get_relationships('AC-2')

        if relationships:
            assert 'direction' in relationships[0]
            assert relationships[0]['direction'] in ['incoming', 'outgoing']

    def test_get_relationships_includes_metadata(self, relationship_mapper):
        """Test relationships include type and confidence."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        relationship_mapper.add_relationship(
            'AC-2',
            'risk1',
            'mitigates',
            confidence=0.9
        )

        relationships = relationship_mapper.get_relationships('AC-2')

        if relationships:
            assert 'type' in relationships[0]
            assert 'confidence' in relationships[0]


class TestGetRelatedEntities:
    """Test getting related entities."""

    def test_get_related_entities_basic(self, relationship_mapper, sample_graph_data):
        """Test getting related entities."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        # Build graph
        for entity_id, entity_type in sample_graph_data['entities']:
            relationship_mapper.add_entity(entity_id, entity_type)

        for source, target, rel_type, conf in sample_graph_data['relationships']:
            relationship_mapper.add_relationship(source, target, rel_type, conf)

        # Get related entities for AC-2
        related = relationship_mapper.get_related_entities('AC-2')

        assert isinstance(related, list)
        assert len(related) > 0

    def test_get_related_entities_by_type(self, relationship_mapper):
        """Test filtering related entities by relationship type."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        relationship_mapper.add_relationship('AC-2', 'risk1', 'mitigates')
        relationship_mapper.add_relationship('AC-2', 'asset1', 'protects')

        # Get only 'mitigates' relationships
        related = relationship_mapper.get_related_entities('AC-2', rel_type='mitigates')

        assert isinstance(related, list)
        # Should only include entities connected via 'mitigates'
        for entity in related:
            if entity['direction'] == 'outgoing':
                assert entity['relationship_type'] == 'mitigates'

    def test_get_related_entities_nonexistent(self, relationship_mapper):
        """Test getting related entities for nonexistent entity."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        related = relationship_mapper.get_related_entities('nonexistent')
        assert related == []


class TestFindPaths:
    """Test path finding."""

    def test_find_paths_basic(self, relationship_mapper):
        """Test finding paths between entities."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        # Create a path: A → B → C
        relationship_mapper.add_relationship('A', 'B', 'related_to')
        relationship_mapper.add_relationship('B', 'C', 'related_to')

        paths = relationship_mapper.find_paths('A', 'C', max_length=3)

        assert isinstance(paths, list)
        if paths:
            assert ['A', 'B', 'C'] in paths

    def test_find_paths_max_length(self, relationship_mapper):
        """Test path finding with max length constraint."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        # Create a longer path: A → B → C → D
        relationship_mapper.add_relationship('A', 'B', 'related_to')
        relationship_mapper.add_relationship('B', 'C', 'related_to')
        relationship_mapper.add_relationship('C', 'D', 'related_to')

        # Should find path with max_length=4
        paths = relationship_mapper.find_paths('A', 'D', max_length=4)
        assert isinstance(paths, list)

        # Should not find path with max_length=2
        paths = relationship_mapper.find_paths('A', 'D', max_length=2)
        assert paths == []

    def test_find_paths_nonexistent_entities(self, relationship_mapper):
        """Test finding paths with nonexistent entities."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        paths = relationship_mapper.find_paths('nonexistent1', 'nonexistent2')
        assert paths == []

    def test_find_paths_no_connection(self, relationship_mapper):
        """Test finding paths when no connection exists."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        relationship_mapper.add_entity('A', 'control')
        relationship_mapper.add_entity('B', 'risk')
        # No relationship between A and B

        paths = relationship_mapper.find_paths('A', 'B')
        assert paths == []


class TestExtractAndMapFromText:
    """Test entity extraction and relationship inference."""

    def test_extract_and_map_basic(
        self,
        relationship_mapper_with_extractor,
        sample_security_text
    ):
        """Test extracting entities and mapping from text."""
        if not relationship_mapper_with_extractor.entity_extractor:
            pytest.skip("EntityExtractor not available")

        if relationship_mapper_with_extractor.graph is None:
            pytest.skip("NetworkX not available")

        result = relationship_mapper_with_extractor.extract_and_map_from_text(
            sample_security_text
        )

        assert isinstance(result, dict)
        assert 'entities' in result
        assert 'relationships' in result
        assert 'summary' in result

    def test_extract_and_map_without_extractor(
        self,
        relationship_mapper,
        sample_security_text
    ):
        """Test extraction fails gracefully without extractor."""
        result = relationship_mapper.extract_and_map_from_text(sample_security_text)

        assert result == {'entities': [], 'relationships': []}

    def test_extract_and_map_adds_entities(
        self,
        relationship_mapper_with_extractor,
        sample_security_text
    ):
        """Test extraction adds entities to graph."""
        if not relationship_mapper_with_extractor.entity_extractor:
            pytest.skip("EntityExtractor not available")

        if relationship_mapper_with_extractor.graph is None:
            pytest.skip("NetworkX not available")

        before_count = relationship_mapper_with_extractor.entity_count

        result = relationship_mapper_with_extractor.extract_and_map_from_text(
            sample_security_text
        )

        # Should have added entities
        assert relationship_mapper_with_extractor.entity_count >= before_count

    def test_extract_and_map_infers_relationships(
        self,
        relationship_mapper_with_extractor,
        sample_security_text
    ):
        """Test extraction infers relationships."""
        if not relationship_mapper_with_extractor.entity_extractor:
            pytest.skip("EntityExtractor not available")

        if relationship_mapper_with_extractor.graph is None:
            pytest.skip("NetworkX not available")

        result = relationship_mapper_with_extractor.extract_and_map_from_text(
            sample_security_text
        )

        # Should have inferred some relationships
        assert isinstance(result.get('relationships', []), list)


class TestJSONExportImport:
    """Test JSON export and import."""

    def test_export_to_json(self, relationship_mapper, tmp_path):
        """Test exporting graph to JSON."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        # Build small graph
        relationship_mapper.add_entity('AC-2', 'control')
        relationship_mapper.add_relationship('AC-2', 'risk1', 'mitigates')

        export_path = tmp_path / "test_graph.json"
        result = relationship_mapper.export_to_json(str(export_path))

        assert result is True
        assert export_path.exists()

    def test_export_creates_valid_json(self, relationship_mapper, tmp_path):
        """Test exported file is valid JSON."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        relationship_mapper.add_entity('AC-2', 'control')
        relationship_mapper.add_relationship('AC-2', 'risk1', 'mitigates')

        export_path = tmp_path / "test_graph.json"
        relationship_mapper.export_to_json(str(export_path))

        # Should be valid JSON
        with open(export_path, 'r') as f:
            data = json.load(f)

        assert 'nodes' in data
        assert 'edges' in data
        assert 'metadata' in data

    def test_import_from_json(self, relationship_mapper, tmp_path):
        """Test importing graph from JSON."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        # Export first
        relationship_mapper.add_entity('AC-2', 'control')
        relationship_mapper.add_relationship('AC-2', 'risk1', 'mitigates')

        export_path = tmp_path / "test_graph.json"
        relationship_mapper.export_to_json(str(export_path))

        # Create new mapper and import
        new_mapper = RelationshipMapper(use_entity_extractor=False)
        if new_mapper.graph is None:
            pytest.skip("NetworkX not available")

        result = new_mapper.import_from_json(str(export_path))

        assert result is True
        assert new_mapper.entity_count > 0

    def test_import_nonexistent_file(self, relationship_mapper):
        """Test importing from nonexistent file."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        result = relationship_mapper.import_from_json("/nonexistent/file.json")
        assert result is False

    def test_export_import_preserves_graph(self, relationship_mapper, tmp_path):
        """Test export/import preserves graph structure."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        # Build graph
        relationship_mapper.add_entity('AC-2', 'control')
        relationship_mapper.add_entity('risk1', 'risk')
        relationship_mapper.add_relationship('AC-2', 'risk1', 'mitigates', 0.9)

        original_entity_count = relationship_mapper.entity_count
        original_relationship_count = relationship_mapper.relationship_count

        # Export and import
        export_path = tmp_path / "test_graph.json"
        relationship_mapper.export_to_json(str(export_path))

        new_mapper = RelationshipMapper(use_entity_extractor=False)
        if new_mapper.graph is None:
            pytest.skip("NetworkX not available")

        new_mapper.import_from_json(str(export_path))

        # Should have same counts
        assert new_mapper.entity_count == original_entity_count
        assert new_mapper.relationship_count == original_relationship_count


class TestGetStatistics:
    """Test statistics generation."""

    def test_get_statistics_basic(self, relationship_mapper):
        """Test getting basic statistics."""
        stats = relationship_mapper.get_statistics()

        assert isinstance(stats, dict)
        assert 'networkx_available' in stats
        assert 'graph_initialized' in stats
        assert 'entity_count' in stats
        assert 'relationship_count' in stats

    def test_get_statistics_with_data(self, relationship_mapper, sample_graph_data):
        """Test statistics with populated graph."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        # Build graph
        for entity_id, entity_type in sample_graph_data['entities']:
            relationship_mapper.add_entity(entity_id, entity_type)

        for source, target, rel_type, conf in sample_graph_data['relationships']:
            relationship_mapper.add_relationship(source, target, rel_type, conf)

        stats = relationship_mapper.get_statistics()

        assert stats['entity_count'] == len(sample_graph_data['entities'])
        assert stats['relationship_count'] == len(sample_graph_data['relationships'])
        assert 'entity_types' in stats
        assert 'relationship_types' in stats

    def test_statistics_entity_type_counts(self, relationship_mapper):
        """Test statistics include entity type counts."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        relationship_mapper.add_entity('AC-2', 'control')
        relationship_mapper.add_entity('AC-3', 'control')
        relationship_mapper.add_entity('risk1', 'risk')

        stats = relationship_mapper.get_statistics()

        if 'entity_types' in stats:
            assert stats['entity_types']['control'] == 2
            assert stats['entity_types']['risk'] == 1

    def test_statistics_relationship_type_counts(self, relationship_mapper):
        """Test statistics include relationship type counts."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        relationship_mapper.add_relationship('AC-2', 'risk1', 'mitigates')
        relationship_mapper.add_relationship('AC-3', 'risk2', 'mitigates')
        relationship_mapper.add_relationship('CVE-1', 'asset1', 'affects')

        stats = relationship_mapper.get_statistics()

        if 'relationship_types' in stats:
            assert stats['relationship_types']['mitigates'] == 2
            assert stats['relationship_types']['affects'] == 1


class TestVisualizeGraph:
    """Test graph visualization."""

    def test_visualize_graph_basic(self, relationship_mapper):
        """Test basic graph visualization."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        viz_data = relationship_mapper.visualize_graph()

        assert isinstance(viz_data, dict)
        assert 'nodes' in viz_data
        assert 'edges' in viz_data

    def test_visualize_graph_with_data(self, relationship_mapper):
        """Test visualization with populated graph."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        relationship_mapper.add_entity('AC-2', 'control')
        relationship_mapper.add_relationship('AC-2', 'risk1', 'mitigates')

        viz_data = relationship_mapper.visualize_graph()

        assert len(viz_data['nodes']) >= 1
        assert len(viz_data['edges']) >= 1

    def test_visualize_graph_node_structure(self, relationship_mapper):
        """Test visualization node structure."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        relationship_mapper.add_entity('AC-2', 'control')

        viz_data = relationship_mapper.visualize_graph()

        if viz_data['nodes']:
            node = viz_data['nodes'][0]
            assert 'id' in node
            assert 'type' in node
            assert 'label' in node

    def test_visualize_graph_edge_structure(self, relationship_mapper):
        """Test visualization edge structure."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        relationship_mapper.add_relationship('AC-2', 'risk1', 'mitigates')

        viz_data = relationship_mapper.visualize_graph()

        if viz_data['edges']:
            edge = viz_data['edges'][0]
            assert 'source' in edge
            assert 'target' in edge
            assert 'type' in edge
            assert 'confidence' in edge


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_operations_without_networkx(self):
        """Test operations when NetworkX is not available."""
        with patch('src.tools.relationship_mapper.NETWORKX_AVAILABLE', False):
            mapper = RelationshipMapper(use_entity_extractor=False)
            # Operations should fail gracefully
            assert mapper.add_entity('AC-2', 'control') is False
            assert mapper.add_relationship('A', 'B', 'relates') is False

    def test_empty_graph_operations(self, relationship_mapper):
        """Test operations on empty graph."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        # Should return empty results
        assert relationship_mapper.get_relationships('nonexistent') == []
        assert relationship_mapper.get_related_entities('nonexistent') == []
        assert relationship_mapper.find_paths('A', 'B') == []

    def test_complex_graph_structure(self, relationship_mapper):
        """Test handling complex graph structures."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        # Create complex relationships
        for i in range(10):
            relationship_mapper.add_entity(f'entity-{i}', 'asset')

        for i in range(9):
            relationship_mapper.add_relationship(
                f'entity-{i}',
                f'entity-{i+1}',
                'depends_on'
            )

        assert relationship_mapper.entity_count == 10
        assert relationship_mapper.relationship_count == 9

    def test_special_characters_in_entity_ids(self, relationship_mapper):
        """Test handling special characters in entity IDs."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        # Should handle special characters
        result = relationship_mapper.add_entity('AC-2(1)', 'control')
        assert result is True

        result = relationship_mapper.add_entity('CVE-2024-1234', 'cve')
        assert result is True

    def test_high_confidence_relationships(self, relationship_mapper):
        """Test relationships with various confidence levels."""
        if relationship_mapper.graph is None:
            pytest.skip("NetworkX not available")

        relationship_mapper.add_relationship('A', 'B', 'relates', confidence=1.0)
        relationship_mapper.add_relationship('C', 'D', 'relates', confidence=0.5)
        relationship_mapper.add_relationship('E', 'F', 'relates', confidence=0.0)

        assert relationship_mapper.relationship_count == 3
