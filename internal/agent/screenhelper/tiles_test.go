package screenhelper

import (
	"image"
	"image/color"
	"testing"
)

func TestChangedStrips(t *testing.T) {
	a := image.NewRGBA(image.Rect(0, 0, 200, 130))
	if got := changedStrips(nil, a); len(got) != 3 || got[0] != image.Rect(0, 0, 200, 64) || got[2] != image.Rect(0, 128, 200, 130) {
		t.Fatalf("first frame: %v", got)
	}
	b := cropCopy(nil, a, a.Rect)
	if got := changedStrips(a, b); len(got) != 0 {
		t.Fatalf("unchanged: %v", got)
	}
	// Two adjacent changed tiles make one strip; a lone one in the last,
	// narrower column, another.
	b.Set(70, 10, color.White)
	b.Set(130, 60, color.White)
	b.Set(199, 129, color.White)
	got := changedStrips(a, b)
	want := []image.Rectangle{image.Rect(64, 0, 192, 64), image.Rect(192, 128, 200, 130)}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("changes = %v, want %v", got, want)
	}
}

func TestCropCopy(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 300, 100))
	src.Set(150, 20, color.White)
	dst := cropCopy(nil, src, image.Rect(100, 0, 300, 100))
	if dst.Rect != image.Rect(0, 0, 200, 100) || dst.RGBAAt(50, 20) != (color.RGBA{255, 255, 255, 255}) {
		t.Fatalf("crop: %v %v", dst.Rect, dst.RGBAAt(50, 20))
	}
	if again := cropCopy(dst, src, image.Rect(100, 0, 300, 100)); again != dst {
		t.Fatal("buffer not reused")
	}
}
