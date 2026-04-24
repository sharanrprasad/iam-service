package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/pressly/goose/v3"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("expected 'up', 'down', or 'create' subcommands")
	}

	// --- Subcommands ---
	upCmd := flag.NewFlagSet("up", flag.ExitOnError)
	upDir := upCmd.String("dir", "database/migrations", "migration directory")

	downCmd := flag.NewFlagSet("down", flag.ExitOnError)
	downDir := downCmd.String("dir", "database/migrations", "migration directory")

	createCmd := flag.NewFlagSet("create", flag.ExitOnError)
	createDir := createCmd.String("dir", "database/migrations", "migration directory")
	createType := createCmd.String("type", "sql", "migration type (sql|go)")

	// --- Common DB config ---
	host := envOrDefault("DB_HOST", "localhost")
	port := envOrDefault("DB_PORT", "3306")
	user := envOrDefault("DB_USER", "iam")
	password := envOrDefault("DB_PASSWORD", "secret")
	dbName := envOrDefault("DB_NAME", "iam_db")

	// Set dialect once
	if err := goose.SetDialect("mysql"); err != nil {
		log.Fatalf("goose.SetDialect: %v", err)
	}

	switch os.Args[1] {

	case "up":
		upCmd.Parse(os.Args[2:])
		runWithDB("up", *upDir, host, port, user, password, dbName, upCmd.Args())

	case "down":
		downCmd.Parse(os.Args[2:])
		runWithDB("down", *downDir, host, port, user, password, dbName, downCmd.Args())

	case "create":
		createCmd.Parse(os.Args[2:])

		if len(createCmd.Args()) < 1 {
			log.Fatalf("usage: create [flags] <migration_name>")
		}

		name := createCmd.Args()[0]

		if err := goose.Create(nil, *createDir, name, *createType); err != nil {
			log.Fatalf("goose.Create: %v", err)
		}

		fmt.Println("Migration created successfully")

	default:
		log.Fatalf("unknown command: %s", os.Args[1])
	}
}

func runWithDB(command, dir, host, port, user, password, dbName string, args []string) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&multiStatements=true",
		user, password, host, port, dbName,
	)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		log.Fatalf("db.Ping: %v", err)
	}

	ctx := context.Background()

	if err := goose.RunContext(ctx, command, db, dir, args...); err != nil {
		log.Fatalf("goose.Run(%s): %v", command, err)
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
