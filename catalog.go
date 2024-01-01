package nb9

import (
	"bytes"
	_ "embed"
	"encoding/json"

	"github.com/bokwoon95/sqddl/ddl"
)

type rawTable struct {
	Table      string   `json:"table"`
	PrimaryKey []string `json:"primarykey"`
	Columns    []struct {
		Column     string            `json:"column"`
		Type       map[string]string `json:"type"`
		Index      bool              `json:"index"`
		PrimaryKey bool              `json:"primarykey"`
		Unique     bool              `json:"unique"`
		NotNull    bool              `json:"notnull"`
		References struct {
			Table  string `json:"table"`
			Column string `json:"column"`
		} `json:"references"`
	} `json:"columns"`
}

//go:embed catalog_files.json
var filesCatalogBytes []byte

func FilesCatalog(dialect string) (*ddl.Catalog, error) {
	return unmarshalCatalog(dialect, filesCatalogBytes)
}

//go:embed catalog_users.json
var usersCatalogBytes []byte

func UsersCatalog(dialect string) (*ddl.Catalog, error) {
	return unmarshalCatalog(dialect, usersCatalogBytes)
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
			cache.AddOrUpdateColumn(table, ddl.Column{
				ColumnName:   rawColumn.Column,
				ColumnType:   columnType,
				IsPrimaryKey: rawColumn.PrimaryKey,
				IsUnique:     rawColumn.Unique,
				IsNotNull:    rawColumn.NotNull,
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
	}
	return catalog, nil
}
