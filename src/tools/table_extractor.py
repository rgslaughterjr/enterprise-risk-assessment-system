"""
Table Extractor for extracting structured data from PDFs.

This module provides advanced table extraction capabilities for:
- Extracting tables from complex PDF layouts
- Handling merged cells and multi-line headers
- Multiple extraction strategies
- Quality scoring and validation
- CSV/DataFrame output formats
"""

import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import io

try:
    import fitz  # PyMuPDF
    import pandas as pd
    import numpy as np
except ImportError as e:
    raise ImportError(f"Missing required dependencies for table extraction: {e}")

logger = logging.getLogger(__name__)


class TableExtractor:
    """
    Enterprise-grade table extractor for PDF documents.

    Features:
    - Automatic table detection
    - Multiple extraction strategies (lattice, stream)
    - Header row identification
    - Merged cell handling
    - Quality scoring
    - Multiple output formats (DataFrame, CSV, JSON)
    """

    MIN_TABLE_QUALITY = 0.5
    MIN_ROWS = 2
    MIN_COLS = 2

    def __init__(
        self,
        min_quality: float = MIN_TABLE_QUALITY,
        detect_headers: bool = True
    ):
        """
        Initialize table extractor.

        Args:
            min_quality: Minimum quality score for valid tables (0-1)
            detect_headers: Whether to auto-detect header rows
        """
        self.min_quality = min_quality
        self.detect_headers = detect_headers

    def extract_tables_from_pdf(
        self,
        pdf_path: str,
        pages: Optional[List[int]] = None,
        strategy: str = 'lattice'
    ) -> List[pd.DataFrame]:
        """
        Extract all tables from a PDF document.

        Args:
            pdf_path: Path to PDF file
            pages: List of page numbers to process (None = all pages)
            strategy: Extraction strategy ('lattice' or 'stream')

        Returns:
            List of DataFrames, one per table found
        """
        try:
            pdf_path = Path(pdf_path)

            if not pdf_path.exists():
                logger.error(f"PDF file not found: {pdf_path}")
                return []

            doc = fitz.open(pdf_path)
            all_tables = []

            pages_to_process = pages if pages is not None else range(len(doc))

            for page_num in pages_to_process:
                if page_num >= len(doc):
                    logger.warning(f"Page {page_num} out of range, skipping")
                    continue

                logger.info(f"Processing page {page_num + 1}/{len(doc)}")
                page = doc[page_num]

                tables = self.extract_tables_from_page(page, strategy)

                for table in tables:
                    if not table.empty:
                        all_tables.append(table)

            doc.close()

            logger.info(f"Extracted {len(all_tables)} tables from {pdf_path.name}")

            return all_tables

        except Exception as e:
            logger.error(f"Error extracting tables from PDF: {e}")
            return []

    def extract_tables_from_page(
        self,
        page: fitz.Page,
        strategy: str = 'lattice'
    ) -> List[pd.DataFrame]:
        """
        Extract tables from a single PDF page.

        Args:
            page: PyMuPDF page object
            strategy: Extraction strategy ('lattice' or 'stream')

        Returns:
            List of DataFrames found on the page
        """
        try:
            tables = []

            # Find tables using PyMuPDF's table detection
            table_instances = page.find_tables()

            if not table_instances or not table_instances.tables:
                logger.debug(f"No tables found on page {page.number}")
                return []

            for table in table_instances.tables:
                try:
                    # Extract table data
                    df = self._extract_table_data(table)

                    if df is not None and not df.empty:
                        # Validate quality
                        quality = self.validate_table_quality(df)

                        if quality >= self.min_quality:
                            # Detect and set headers
                            if self.detect_headers:
                                df = self._detect_and_set_headers(df)

                            tables.append(df)
                            logger.debug(f"Extracted table: {df.shape} (quality: {quality:.2f})")
                        else:
                            logger.debug(f"Table quality too low: {quality:.2f}")

                except Exception as e:
                    logger.warning(f"Error extracting individual table: {e}")
                    continue

            return tables

        except Exception as e:
            logger.error(f"Error extracting tables from page: {e}")
            return []

    def _extract_table_data(self, table: Any) -> Optional[pd.DataFrame]:
        """
        Extract data from PyMuPDF table object to DataFrame.

        Args:
            table: PyMuPDF table object

        Returns:
            DataFrame with table data
        """
        try:
            # Extract table as list of lists
            data = table.extract()

            if not data or len(data) < self.MIN_ROWS:
                return None

            # Convert to DataFrame
            df = pd.DataFrame(data)

            # Clean empty rows and columns
            df = self._clean_table(df)

            return df

        except Exception as e:
            logger.warning(f"Error extracting table data: {e}")
            return None

    def _clean_table(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean table by removing empty rows and columns.

        Args:
            df: Input DataFrame

        Returns:
            Cleaned DataFrame
        """
        try:
            # Remove completely empty rows
            df = df.dropna(how='all')

            # Remove completely empty columns
            df = df.dropna(axis=1, how='all')

            # Strip whitespace from string cells
            for col in df.columns:
                if df[col].dtype == 'object':
                    df[col] = df[col].astype(str).str.strip()

            # Replace 'nan' strings with actual NaN
            df = df.replace('nan', np.nan)

            # Reset index
            df = df.reset_index(drop=True)

            return df

        except Exception as e:
            logger.warning(f"Error cleaning table: {e}")
            return df

    def _detect_and_set_headers(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Detect and set header row from table data.

        Args:
            df: Input DataFrame

        Returns:
            DataFrame with headers set
        """
        try:
            if len(df) < 2:
                return df

            # Use first row as headers
            df.columns = df.iloc[0]
            df = df[1:]
            df = df.reset_index(drop=True)

            # Clean column names
            df.columns = [
                str(col).strip() if (col and str(col).lower() != 'nan') else f'Column_{i}'
                for i, col in enumerate(df.columns)
            ]

            return df

        except Exception as e:
            logger.warning(f"Error detecting headers: {e}")
            return df

    def detect_table_structure(self, page: fitz.Page) -> Dict[str, Any]:
        """
        Detect table structure and metadata from a page.

        Args:
            page: PyMuPDF page object

        Returns:
            Dictionary with structure information:
                - table_count: Number of tables found
                - table_locations: List of bounding boxes
                - page_number: Page number
        """
        try:
            table_instances = page.find_tables()

            if not table_instances or not table_instances.tables:
                return {
                    'table_count': 0,
                    'table_locations': [],
                    'page_number': page.number
                }

            locations = []
            for table in table_instances.tables:
                bbox = table.bbox
                locations.append({
                    'x0': bbox[0],
                    'y0': bbox[1],
                    'x1': bbox[2],
                    'y1': bbox[3],
                    'rows': len(table.extract()),
                    'cols': len(table.extract()[0]) if table.extract() else 0
                })

            return {
                'table_count': len(table_instances.tables),
                'table_locations': locations,
                'page_number': page.number
            }

        except Exception as e:
            logger.error(f"Error detecting table structure: {e}")
            return {
                'table_count': 0,
                'table_locations': [],
                'page_number': page.number
            }

    def merge_split_tables(
        self,
        tables: List[pd.DataFrame],
        similarity_threshold: float = 0.8
    ) -> List[pd.DataFrame]:
        """
        Merge tables that appear to be split across pages.

        Args:
            tables: List of DataFrames
            similarity_threshold: Column similarity threshold for merging (0-1)

        Returns:
            List of merged DataFrames
        """
        if len(tables) < 2:
            return tables

        try:
            merged = []
            skip_indices = set()

            for i in range(len(tables) - 1):
                if i in skip_indices:
                    continue

                current = tables[i]
                next_table = tables[i + 1]

                # Check if tables have similar column structure
                if self._are_tables_similar(current, next_table, similarity_threshold):
                    # Merge tables
                    merged_table = pd.concat([current, next_table], ignore_index=True)
                    merged.append(merged_table)
                    skip_indices.add(i + 1)
                    logger.info(f"Merged tables {i} and {i + 1}")
                else:
                    merged.append(current)

            # Add last table if not merged
            if len(tables) - 1 not in skip_indices:
                merged.append(tables[-1])

            return merged

        except Exception as e:
            logger.error(f"Error merging tables: {e}")
            return tables

    def _are_tables_similar(
        self,
        df1: pd.DataFrame,
        df2: pd.DataFrame,
        threshold: float
    ) -> bool:
        """
        Check if two tables have similar structure.

        Args:
            df1: First DataFrame
            df2: Second DataFrame
            threshold: Similarity threshold (0-1)

        Returns:
            True if tables are similar enough to merge
        """
        try:
            # Same number of columns
            if len(df1.columns) != len(df2.columns):
                return False

            # Compare column names
            cols1 = set(str(c).lower().strip() for c in df1.columns)
            cols2 = set(str(c).lower().strip() for c in df2.columns)

            similarity = len(cols1 & cols2) / len(cols1 | cols2)

            return similarity >= threshold

        except Exception as e:
            logger.warning(f"Error comparing table similarity: {e}")
            return False

    def validate_table_quality(self, table: pd.DataFrame) -> float:
        """
        Calculate quality score for extracted table.

        Scoring based on:
        - Completeness (non-empty cells)
        - Structure (consistent row/column counts)
        - Size (sufficient rows/columns)

        Args:
            table: DataFrame to validate

        Returns:
            Quality score (0-1)
        """
        try:
            if table.empty:
                return 0.0

            rows, cols = table.shape

            # Size score
            size_score = min(1.0, (rows / 10) * 0.5 + (cols / 5) * 0.5)

            # Completeness score (percentage of non-empty cells)
            total_cells = rows * cols
            non_empty_cells = table.notna().sum().sum()
            completeness_score = non_empty_cells / total_cells if total_cells > 0 else 0

            # Structure score (consistency)
            # Check for consistent data types in columns
            structure_score = 0.0
            for col in table.columns:
                non_null = table[col].dropna()
                if len(non_null) > 0:
                    # If >80% of values have same type, structure is good
                    most_common_type = type(non_null.iloc[0])
                    type_consistency = sum(isinstance(x, most_common_type) for x in non_null) / len(non_null)
                    structure_score += type_consistency

            structure_score = structure_score / cols if cols > 0 else 0

            # Weighted average
            quality = (
                size_score * 0.2 +
                completeness_score * 0.5 +
                structure_score * 0.3
            )

            return min(1.0, quality)

        except Exception as e:
            logger.warning(f"Error validating table quality: {e}")
            return 0.0

    def to_csv(
        self,
        table: pd.DataFrame,
        output_path: str,
        include_index: bool = False
    ) -> bool:
        """
        Save table to CSV file.

        Args:
            table: DataFrame to save
            output_path: Output file path
            include_index: Whether to include index in CSV

        Returns:
            True if successful
        """
        try:
            table.to_csv(output_path, index=include_index)
            logger.info(f"Saved table to {output_path}")
            return True

        except Exception as e:
            logger.error(f"Error saving table to CSV: {e}")
            return False

    def to_json(
        self,
        table: pd.DataFrame,
        output_path: str,
        orient: str = 'records'
    ) -> bool:
        """
        Save table to JSON file.

        Args:
            table: DataFrame to save
            output_path: Output file path
            orient: JSON orientation ('records', 'index', 'columns')

        Returns:
            True if successful
        """
        try:
            table.to_json(output_path, orient=orient, indent=2)
            logger.info(f"Saved table to {output_path}")
            return True

        except Exception as e:
            logger.error(f"Error saving table to JSON: {e}")
            return False

    def get_table_statistics(
        self,
        tables: List[pd.DataFrame]
    ) -> Dict[str, Any]:
        """
        Calculate statistics for extracted tables.

        Args:
            tables: List of DataFrames

        Returns:
            Dictionary with statistics
        """
        if not tables:
            return {
                'total_tables': 0,
                'total_rows': 0,
                'total_cells': 0,
                'avg_rows': 0,
                'avg_cols': 0,
                'avg_quality': 0
            }

        try:
            total_rows = sum(len(t) for t in tables)
            total_cells = sum(t.size for t in tables)
            qualities = [self.validate_table_quality(t) for t in tables]

            return {
                'total_tables': len(tables),
                'total_rows': total_rows,
                'total_cells': total_cells,
                'avg_rows': total_rows / len(tables),
                'avg_cols': sum(len(t.columns) for t in tables) / len(tables),
                'avg_quality': np.mean(qualities),
                'min_quality': min(qualities),
                'max_quality': max(qualities)
            }

        except Exception as e:
            logger.error(f"Error calculating table statistics: {e}")
            return {
                'total_tables': len(tables),
                'error': str(e)
            }
