package nb9

import (
	"bytes"
	_ "embed"
	"encoding/json"

	"github.com/bokwoon95/sqddl/ddl"
)

type rawTable struct {
	Table      string
	PrimaryKey []string
	Columns    []struct {
		Dialect   string
		Column    string
		Type      map[string]string
		Generated struct {
			Expression string
			Stored     bool
		}
		Index      bool
		PrimaryKey bool
		Unique     bool
		NotNull    bool
		References struct {
			Table  string
			Column string
		}
	}
	Indexes []struct {
		Dialect string
		Type    string
		Columns []string
	}
}

//go:embed catalog_files.json
var filesCatalogBytes []byte

func FilesCatalog(dialect string) (*ddl.Catalog, error) {
	return unmarshalCatalog(dialect, filesCatalogBytes)
}

//go:embed catalog.json
var catalogBytes []byte

func Catalog(dialect string) (*ddl.Catalog, error) {
	return unmarshalCatalog(dialect, catalogBytes)
}

func unmarshalCatalog(dialect string, b []byte) (*ddl.Catalog, error) {
	var rawTables []rawTable
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&rawTables)
	if err != nil {
		return nil, err
	}
	catalog := &ddl.Catalog{
		Dialect: dialect,
	}
	cache := ddl.NewCatalogCache(catalog)
	schema := cache.GetOrCreateSchema(catalog, "")
	for _, rawTable := range rawTables {
		table := cache.GetOrCreateTable(schema, rawTable.Table)
		if len(rawTable.PrimaryKey) != 0 {
			cache.AddOrUpdateConstraint(table, ddl.Constraint{
				ConstraintName: ddl.GenerateName(ddl.PRIMARY_KEY, rawTable.Table, rawTable.PrimaryKey),
				ConstraintType: ddl.PRIMARY_KEY,
				Columns:        rawTable.PrimaryKey,
			})
		}
		for _, rawColumn := range rawTable.Columns {
			columnType := rawColumn.Type[dialect]
			if columnType == "" {
				columnType = rawColumn.Type["default"]
			}
			if rawColumn.Dialect != "" && rawColumn.Dialect != dialect {
				continue
			}
			cache.AddOrUpdateColumn(table, ddl.Column{
				ColumnName:          rawColumn.Column,
				ColumnType:          columnType,
				IsPrimaryKey:        rawColumn.PrimaryKey,
				IsUnique:            rawColumn.Unique,
				IsNotNull:           rawColumn.NotNull,
				GeneratedExpr:       rawColumn.Generated.Expression,
				GeneratedExprStored: rawColumn.Generated.Stored,
			})
			if rawColumn.PrimaryKey {
				cache.AddOrUpdateConstraint(table, ddl.Constraint{
					ConstraintName: ddl.GenerateName(ddl.PRIMARY_KEY, rawTable.Table, []string{rawColumn.Column}),
					ConstraintType: ddl.PRIMARY_KEY,
					Columns:        []string{rawColumn.Column},
				})
			}
			if rawColumn.Unique {
				cache.AddOrUpdateConstraint(table, ddl.Constraint{
					ConstraintName: ddl.GenerateName(ddl.UNIQUE, rawTable.Table, []string{rawColumn.Column}),
					ConstraintType: ddl.UNIQUE,
					Columns:        []string{rawColumn.Column},
				})
			}
			if rawColumn.Index {
				cache.AddOrUpdateIndex(table, ddl.Index{
					IndexName: ddl.GenerateName(ddl.INDEX, rawTable.Table, []string{rawColumn.Column}),
					Columns:   []string{rawColumn.Column},
				})
			}
			if rawColumn.References.Table != "" {
				columnName := rawColumn.References.Column
				if columnName == "" {
					columnName = rawColumn.Column
				}
				cache.AddOrUpdateConstraint(table, ddl.Constraint{
					ConstraintName:    ddl.GenerateName(ddl.FOREIGN_KEY, rawTable.Table, []string{columnName}),
					ConstraintType:    ddl.FOREIGN_KEY,
					Columns:           []string{rawColumn.Column},
					ReferencesTable:   rawColumn.References.Table,
					ReferencesColumns: []string{columnName},
					UpdateRule:        ddl.CASCADE,
				})
			}
		}
		for _, rawIndex := range rawTable.Indexes {
			if rawIndex.Dialect != "" && rawIndex.Dialect != dialect {
				continue
			}
			cache.AddOrUpdateIndex(table, ddl.Index{
				IndexName: ddl.GenerateName(ddl.INDEX, rawTable.Table, rawIndex.Columns),
				IndexType: rawIndex.Type,
				Columns:   rawIndex.Columns,
			})
		}
	}
	return catalog, nil
}
