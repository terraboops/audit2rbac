package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"

	"k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func TestEventToAttributes(t *testing.T) {
	testcases := []struct {
		name               string
		event              *audit.Event
		expectedAttributes authorizer.AttributesRecord
	}{
		{
			name: "rejected create",
			event: &audit.Event{
				Verb: "create",
				ObjectRef: &audit.ObjectReference{
					APIGroup:   "mygroup",
					APIVersion: "myversion",
					Resource:   "myresources",
					Namespace:  "mynamespace",
					// no name attribute in unauthorized create, request body is never parsed
				},
			},
			expectedAttributes: authorizer.AttributesRecord{
				User:            &user.DefaultInfo{},
				Verb:            "create",
				Namespace:       "mynamespace",
				APIGroup:        "mygroup",
				APIVersion:      "myversion",
				Resource:        "myresources",
				ResourceRequest: true,
			},
		},
		{
			name: "accepted create",
			event: &audit.Event{
				Verb: "create",
				ObjectRef: &audit.ObjectReference{
					APIGroup:   "mygroup",
					APIVersion: "myversion",
					Resource:   "myresources",
					Namespace:  "mynamespace",
					Name:       "myname",
				},
			},
			expectedAttributes: authorizer.AttributesRecord{
				User:            &user.DefaultInfo{},
				Verb:            "create",
				Namespace:       "mynamespace",
				APIGroup:        "mygroup",
				APIVersion:      "myversion",
				Resource:        "myresources",
				ResourceRequest: true,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			actualAttributes := eventToAttributes(tc.event)
			if !reflect.DeepEqual(tc.expectedAttributes, actualAttributes) {
				t.Errorf("unexpected diff:\n%s", cmp.Diff(tc.expectedAttributes, actualAttributes))
			}
		})
	}
}

func TestOutputFilename(t *testing.T) {
	run := func(t *testing.T, user, outputFilename string) (string, error) {
		stdout := &bytes.Buffer{}
		options := &Audit2RBACOptions{
			AuditSources:   []string{"../../testdata/demo.log"},
			User:           user,
			GeneratedPath:  ".",
			OutputFilename: outputFilename,
			Stdout:         stdout,
			Stderr:         io.Discard,
		}
		if err := options.Complete("", nil, "audit2rbac:${user}", nil, nil); err != nil {
			t.Fatal(err)
		}
		if err := options.Validate(); err != nil {
			t.Fatal(err)
		}
		err := options.Run()
		return stdout.String(), err
	}

	expected, err := run(t, "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(expected) == 0 {
		t.Fatal("expected output on stdout")
	}

	t.Run("writes file", func(t *testing.T) {
		dir := t.TempDir()
		filename := filepath.Join(dir, "roles.yaml")
		if err := os.WriteFile(filename, []byte("existing content that is longer than the output"+expected), 0644); err != nil {
			t.Fatal(err)
		}
		stdout, err := run(t, "alice", filename)
		if err != nil {
			t.Fatal(err)
		}
		if len(stdout) > 0 {
			t.Errorf("expected no stdout, got %q", stdout)
		}
		data, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != expected {
			t.Errorf("unexpected file content:\n%s", string(data))
		}
		info, err := os.Stat(filename)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0644 {
			t.Errorf("expected 0644, got %v", info.Mode().Perm())
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Errorf("expected only the output file, got %v", entries)
		}
	})

	t.Run("no file on error", func(t *testing.T) {
		dir := t.TempDir()
		filename := filepath.Join(dir, "roles.yaml")
		if _, err := run(t, "nobody", filename); err == nil {
			t.Fatal("expected error")
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Errorf("expected no files, got %v", entries)
		}
	})

	t.Run("missing directory", func(t *testing.T) {
		filename := filepath.Join(t.TempDir(), "missing", "roles.yaml")
		if _, err := run(t, "alice", filename); err == nil {
			t.Fatal("expected error")
		}
	})
}
