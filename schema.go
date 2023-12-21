package nb9

import (
	"bytes"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"io"

	"github.com/bokwoon95/sqddl/ddl"
	"github.com/pelletier/go-toml/v2"
)

//go:embed schema.toml
var schemaBytes []byte

func Automigrate(dialect string, db *sql.DB) error {
	var rawSchema struct {
		Tables []struct {
			Table      string   `toml:"table"`
			PrimaryKey []string `toml:"primarykey"`
			Columns    []struct {
				Column     string            `toml:"column"`
				Type       map[string]string `toml:"type"`
				Index      bool              `toml:"index"`
				Primarykey bool              `toml:"primarykey"`
				Unique     bool              `toml:"unique"`
				NotNull    bool              `toml:"notnull"`
				References struct {
					Table  string `toml:"table"`
					Column string `toml:"column"`
				} `toml:"references"`
			} `toml:"columns"`
		}
	}
	decoder := toml.NewDecoder(bytes.NewReader(schemaBytes))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&rawSchema)
	if err != nil {
		var decodeError *toml.DecodeError
		if errors.As(err, &decodeError) {
			return fmt.Errorf(decodeError.String())
		}
		var strictMissingError *toml.StrictMissingError
		if errors.As(err, &strictMissingError) {
			return fmt.Errorf(strictMissingError.String())
		}
		return err
	}
	catalog := &ddl.Catalog{
		Dialect: dialect,
	}
	cache := ddl.NewCatalogCache(catalog)
	schema := cache.GetOrCreateSchema(catalog, "")
	for _, rawTable := range rawSchema.Tables {
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
				IsPrimaryKey: rawColumn.Primarykey,
				IsUnique:     rawColumn.Unique,
				IsNotNull:    rawColumn.NotNull,
			})
			if rawColumn.Primarykey {
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
	automigrateCmd := &ddl.AutomigrateCmd{
		DB:             db,
		Dialect:        dialect,
		DestCatalog:    catalog,
		DropObjects:    true, // TODO: turn this off when we go live.
		AcceptWarnings: true,
		Stderr:         io.Discard,
	}
	err = automigrateCmd.Run()
	if err != nil {
		return err
	}
	return nil
}
