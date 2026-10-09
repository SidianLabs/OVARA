//go:build windows

package appendfile

import "os"

func truncate(f *os.File, size int64) error {
	g, err := os.OpenFile(f.Name(), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if err := g.Truncate(size); err != nil {
		g.Close()
		return err
	}
	return g.Close()
}
