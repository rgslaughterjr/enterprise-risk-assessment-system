"""
Comprehensive tests for Table Extractor.

Tests cover:
- PDF table extraction
- Table quality validation
- Header detection
- Table merging
- Structure detection
- Export to CSV/JSON
- Statistics calculation
- Error handling
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import pandas as pd
import numpy as np
import tempfile

from src.tools.table_extractor import TableExtractor


@pytest.fixture
def table_extractor():
    """Create table extractor instance."""
    return TableExtractor(min_quality=0.5, detect_headers=True)


@pytest.fixture
def sample_dataframe():
    """Create a sample DataFrame."""
    return pd.DataFrame({
        'Name': ['Alice', 'Bob', 'Charlie'],
        'Age': [25, 30, 35],
        'City': ['New York', 'London', 'Paris']
    })


@pytest.fixture
def mock_pdf_page():
    """Create a mock PDF page."""
    page = MagicMock()
    page.number = 0
    return page


@pytest.fixture
def mock_table():
    """Create a mock table object from PyMuPDF."""
    table = Mock()
    table.bbox = [100, 100, 400, 300]
    table.extract.return_value = [
        ['Name', 'Age', 'City'],
        ['Alice', '25', 'New York'],
        ['Bob', '30', 'London']
    ]
    return table


class TestTableExtractorInit:
    """Test table extractor initialization."""

    def test_init_default_params(self):
        """Test initialization with default parameters."""
        extractor = TableExtractor()
        assert extractor.min_quality == 0.5
        assert extractor.detect_headers is True

    def test_init_custom_params(self):
        """Test initialization with custom parameters."""
        extractor = TableExtractor(min_quality=0.7, detect_headers=False)
        assert extractor.min_quality == 0.7
        assert extractor.detect_headers is False

    def test_constants_defined(self):
        """Test class constants are defined."""
        assert TableExtractor.MIN_TABLE_QUALITY == 0.5
        assert TableExtractor.MIN_ROWS == 2
        assert TableExtractor.MIN_COLS == 2


class TestExtractTablesFromPDF:
    """Test PDF table extraction."""

    @patch('src.tools.table_extractor.fitz.open')
    def test_extract_tables_success(
        self,
        mock_fitz_open,
        table_extractor,
        mock_pdf_page,
        mock_table,
        tmp_path
    ):
        """Test successful table extraction from PDF."""
        test_file = tmp_path / "test.pdf"
        test_file.touch()

        # Mock PDF document
        mock_doc = MagicMock()
        mock_doc.__len__.return_value = 1
        mock_doc.__getitem__.return_value = mock_pdf_page

        # Mock table detection
        mock_tables = Mock()
        mock_tables.tables = [mock_table]
        mock_pdf_page.find_tables.return_value = mock_tables

        mock_fitz_open.return_value = mock_doc

        # Execute
        tables = table_extractor.extract_tables_from_pdf(str(test_file))

        # Verify
        assert len(tables) > 0
        assert isinstance(tables[0], pd.DataFrame)
        mock_doc.close.assert_called_once()

    def test_extract_tables_file_not_found(self, table_extractor):
        """Test extraction with non-existent file."""
        tables = table_extractor.extract_tables_from_pdf("/nonexistent/file.pdf")
        assert tables == []

    @patch('src.tools.table_extractor.fitz.open')
    def test_extract_tables_specific_pages(
        self,
        mock_fitz_open,
        table_extractor,
        mock_pdf_page,
        mock_table,
        tmp_path
    ):
        """Test extraction from specific pages."""
        test_file = tmp_path / "test.pdf"
        test_file.touch()

        mock_doc = MagicMock()
        mock_doc.__len__.return_value = 5
        mock_doc.__getitem__.return_value = mock_pdf_page

        mock_tables = Mock()
        mock_tables.tables = [mock_table]
        mock_pdf_page.find_tables.return_value = mock_tables

        mock_fitz_open.return_value = mock_doc

        # Extract only pages 1 and 2
        tables = table_extractor.extract_tables_from_pdf(str(test_file), pages=[1, 2])

        # Should process 2 pages
        assert mock_pdf_page.find_tables.call_count == 2

    @patch('src.tools.table_extractor.fitz.open')
    def test_extract_tables_exception_handling(
        self,
        mock_fitz_open,
        table_extractor,
        tmp_path
    ):
        """Test exception handling during extraction."""
        test_file = tmp_path / "test.pdf"
        test_file.touch()

        mock_fitz_open.side_effect = Exception("Open error")

        tables = table_extractor.extract_tables_from_pdf(str(test_file))
        assert tables == []


class TestExtractTablesFromPage:
    """Test single page table extraction."""

    def test_extract_from_page_success(
        self,
        table_extractor,
        mock_pdf_page,
        mock_table
    ):
        """Test successful extraction from page."""
        mock_tables = Mock()
        mock_tables.tables = [mock_table]
        mock_pdf_page.find_tables.return_value = mock_tables

        tables = table_extractor.extract_tables_from_page(mock_pdf_page)

        assert len(tables) > 0
        assert isinstance(tables[0], pd.DataFrame)

    def test_extract_from_page_no_tables(
        self,
        table_extractor,
        mock_pdf_page
    ):
        """Test extraction when no tables found."""
        mock_pdf_page.find_tables.return_value = None

        tables = table_extractor.extract_tables_from_page(mock_pdf_page)

        assert tables == []

    def test_extract_from_page_empty_tables(
        self,
        table_extractor,
        mock_pdf_page
    ):
        """Test extraction with empty tables."""
        mock_tables = Mock()
        mock_tables.tables = []
        mock_pdf_page.find_tables.return_value = mock_tables

        tables = table_extractor.extract_tables_from_page(mock_pdf_page)

        assert tables == []


class TestTableCleaning:
    """Test table cleaning functionality."""

    def test_clean_table_removes_empty_rows(self, table_extractor):
        """Test cleaning removes empty rows."""
        df = pd.DataFrame({
            'A': [1, None, 3],
            'B': [4, None, 6]
        })

        cleaned = table_extractor._clean_table(df)

        assert len(cleaned) == 2  # One empty row removed

    def test_clean_table_removes_empty_columns(self, table_extractor):
        """Test cleaning removes empty columns."""
        df = pd.DataFrame({
            'A': [1, 2, 3],
            'B': [None, None, None],
            'C': [7, 8, 9]
        })

        cleaned = table_extractor._clean_table(df)

        assert len(cleaned.columns) == 2  # One empty column removed

    def test_clean_table_strips_whitespace(self, table_extractor):
        """Test cleaning strips whitespace."""
        df = pd.DataFrame({
            'A': ['  text  ', ' data ']
        })

        cleaned = table_extractor._clean_table(df)

        assert cleaned['A'].iloc[0] == 'text'
        assert cleaned['A'].iloc[1] == 'data'


class TestHeaderDetection:
    """Test header detection and setting."""

    def test_detect_and_set_headers(self, table_extractor):
        """Test header detection."""
        df = pd.DataFrame([
            ['Name', 'Age', 'City'],
            ['Alice', 25, 'NYC'],
            ['Bob', 30, 'LA']
        ])

        result = table_extractor._detect_and_set_headers(df)

        assert 'Name' in result.columns
        assert 'Age' in result.columns
        assert 'City' in result.columns
        assert len(result) == 2  # Header row removed from data

    def test_detect_headers_insufficient_rows(self, table_extractor):
        """Test header detection with insufficient rows."""
        df = pd.DataFrame([['A', 'B', 'C']])

        result = table_extractor._detect_and_set_headers(df)

        # Should return unchanged
        assert len(result) == 1

    def test_detect_headers_with_none_values(self, table_extractor):
        """Test header detection with None values."""
        df = pd.DataFrame([
            ['Name', None, 'City'],
            ['Alice', 25, 'NYC']
        ])

        result = table_extractor._detect_and_set_headers(df)

        assert 'Name' in result.columns
        assert 'Column_1' in result.columns  # None replaced
        assert 'City' in result.columns


class TestTableStructureDetection:
    """Test table structure detection."""

    def test_detect_structure_with_tables(
        self,
        table_extractor,
        mock_pdf_page,
        mock_table
    ):
        """Test structure detection with tables present."""
        mock_tables = Mock()
        mock_tables.tables = [mock_table]
        mock_pdf_page.find_tables.return_value = mock_tables

        structure = table_extractor.detect_table_structure(mock_pdf_page)

        assert structure['table_count'] == 1
        assert structure['page_number'] == 0
        assert len(structure['table_locations']) == 1
        assert 'x0' in structure['table_locations'][0]

    def test_detect_structure_no_tables(
        self,
        table_extractor,
        mock_pdf_page
    ):
        """Test structure detection with no tables."""
        mock_pdf_page.find_tables.return_value = None

        structure = table_extractor.detect_table_structure(mock_pdf_page)

        assert structure['table_count'] == 0
        assert structure['table_locations'] == []


class TestTableMerging:
    """Test table merging functionality."""

    def test_merge_similar_tables(self, table_extractor):
        """Test merging tables with similar structure."""
        df1 = pd.DataFrame({
            'Name': ['Alice'],
            'Age': [25]
        })
        df2 = pd.DataFrame({
            'Name': ['Bob'],
            'Age': [30]
        })

        merged = table_extractor.merge_split_tables([df1, df2])

        assert len(merged) == 1
        assert len(merged[0]) == 2  # Combined rows

    def test_merge_dissimilar_tables(self, table_extractor):
        """Test merging tables with different structures."""
        df1 = pd.DataFrame({
            'Name': ['Alice'],
            'Age': [25]
        })
        df2 = pd.DataFrame({
            'City': ['NYC'],
            'Country': ['USA']
        })

        merged = table_extractor.merge_split_tables([df1, df2])

        assert len(merged) == 2  # Not merged

    def test_merge_single_table(self, table_extractor):
        """Test merging with single table."""
        df = pd.DataFrame({'A': [1, 2]})

        merged = table_extractor.merge_split_tables([df])

        assert len(merged) == 1
        assert merged[0].equals(df)

    def test_are_tables_similar(self, table_extractor):
        """Test table similarity check."""
        df1 = pd.DataFrame(columns=['Name', 'Age'])
        df2 = pd.DataFrame(columns=['Name', 'Age'])

        assert table_extractor._are_tables_similar(df1, df2, 0.8) is True

    def test_are_tables_different(self, table_extractor):
        """Test table difference check."""
        df1 = pd.DataFrame(columns=['Name', 'Age'])
        df2 = pd.DataFrame(columns=['City', 'Country'])

        assert table_extractor._are_tables_similar(df1, df2, 0.8) is False


class TestQualityValidation:
    """Test table quality validation."""

    def test_validate_high_quality_table(self, table_extractor):
        """Test validation of high quality table."""
        df = pd.DataFrame({
            'A': [1, 2, 3, 4, 5],
            'B': [10, 20, 30, 40, 50],
            'C': [100, 200, 300, 400, 500]
        })

        quality = table_extractor.validate_table_quality(df)

        assert quality > 0.5

    def test_validate_low_quality_table(self, table_extractor):
        """Test validation of low quality table."""
        df = pd.DataFrame({
            'A': [1, None],
            'B': [None, None]
        })

        quality = table_extractor.validate_table_quality(df)

        assert quality < 0.5

    def test_validate_empty_table(self, table_extractor):
        """Test validation of empty table."""
        df = pd.DataFrame()

        quality = table_extractor.validate_table_quality(df)

        assert quality == 0.0

    def test_validate_sparse_table(self, table_extractor):
        """Test validation of sparse table."""
        df = pd.DataFrame({
            'A': [1, None, None, None],
            'B': [None, 2, None, None],
            'C': [None, None, None, 3]
        })

        quality = table_extractor.validate_table_quality(df)

        assert 0.0 < quality < 0.5


class TestExportFunctions:
    """Test table export functionality."""

    def test_to_csv_success(self, table_extractor, sample_dataframe, tmp_path):
        """Test successful CSV export."""
        output_file = tmp_path / "test.csv"

        result = table_extractor.to_csv(sample_dataframe, str(output_file))

        assert result is True
        assert output_file.exists()

    def test_to_csv_with_index(self, table_extractor, sample_dataframe, tmp_path):
        """Test CSV export with index."""
        output_file = tmp_path / "test.csv"

        result = table_extractor.to_csv(
            sample_dataframe,
            str(output_file),
            include_index=True
        )

        assert result is True

    def test_to_csv_exception(self, table_extractor, sample_dataframe):
        """Test CSV export exception handling."""
        result = table_extractor.to_csv(
            sample_dataframe,
            "/invalid/path/file.csv"
        )

        assert result is False

    def test_to_json_success(self, table_extractor, sample_dataframe, tmp_path):
        """Test successful JSON export."""
        output_file = tmp_path / "test.json"

        result = table_extractor.to_json(sample_dataframe, str(output_file))

        assert result is True
        assert output_file.exists()

    def test_to_json_different_orient(self, table_extractor, sample_dataframe, tmp_path):
        """Test JSON export with different orientation."""
        output_file = tmp_path / "test.json"

        result = table_extractor.to_json(
            sample_dataframe,
            str(output_file),
            orient='index'
        )

        assert result is True

    def test_to_json_exception(self, table_extractor, sample_dataframe):
        """Test JSON export exception handling."""
        result = table_extractor.to_json(
            sample_dataframe,
            "/invalid/path/file.json"
        )

        assert result is False


class TestStatistics:
    """Test table statistics calculation."""

    def test_get_statistics_multiple_tables(
        self,
        table_extractor,
        sample_dataframe
    ):
        """Test statistics with multiple tables."""
        tables = [sample_dataframe, sample_dataframe, sample_dataframe]

        stats = table_extractor.get_table_statistics(tables)

        assert stats['total_tables'] == 3
        assert stats['total_rows'] == 9
        assert stats['avg_rows'] == 3
        assert stats['avg_cols'] == 3
        assert 'avg_quality' in stats

    def test_get_statistics_empty_list(self, table_extractor):
        """Test statistics with empty list."""
        stats = table_extractor.get_table_statistics([])

        assert stats['total_tables'] == 0
        assert stats['total_rows'] == 0
        assert stats['avg_quality'] == 0

    def test_get_statistics_single_table(
        self,
        table_extractor,
        sample_dataframe
    ):
        """Test statistics with single table."""
        stats = table_extractor.get_table_statistics([sample_dataframe])

        assert stats['total_tables'] == 1
        assert stats['total_rows'] == 3
        assert stats['total_cells'] == 9


class TestExtractTableData:
    """Test table data extraction."""

    def test_extract_table_data_success(self, table_extractor, mock_table):
        """Test successful table data extraction."""
        df = table_extractor._extract_table_data(mock_table)

        assert df is not None
        assert isinstance(df, pd.DataFrame)
        assert not df.empty

    def test_extract_table_data_insufficient_rows(self, table_extractor):
        """Test extraction with insufficient rows."""
        mock_table = Mock()
        mock_table.extract.return_value = [['A', 'B']]  # Only 1 row

        df = table_extractor._extract_table_data(mock_table)

        assert df is None

    def test_extract_table_data_exception(self, table_extractor):
        """Test exception handling in data extraction."""
        mock_table = Mock()
        mock_table.extract.side_effect = Exception("Extract error")

        df = table_extractor._extract_table_data(mock_table)

        assert df is None
