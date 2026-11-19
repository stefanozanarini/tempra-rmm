package screenhelper

import (
	"bytes"
	"image"
)

// tileSize is the side of the squares compared between two frames: small
// enough that a blinking cursor sends little, large enough that a JPEG per
// changed strip stays worth its header.
const tileSize = 64

// changedStrips compares cur with prev, an image of the same size, and
// returns the parts that differ, as horizontal strips of adjacent changed
// tiles. With prev nil, every tile row is one strip.
func changedStrips(prev, cur *image.RGBA) []image.Rectangle {
	b := cur.Rect
	var out []image.Rectangle
	for y := b.Min.Y; y < b.Max.Y; y += tileSize {
		y1 := min(y+tileSize, b.Max.Y)
		start := -1
		for x := b.Min.X; x < b.Max.X; x += tileSize {
			changed := prev == nil || tileDiffers(prev, cur, image.Rect(x, y, min(x+tileSize, b.Max.X), y1))
			switch {
			case changed && start < 0:
				start = x
			case !changed && start >= 0:
				out = append(out, image.Rect(start, y, x, y1))
				start = -1
			}
		}
		if start >= 0 {
			out = append(out, image.Rect(start, y, b.Max.X, y1))
		}
	}
	return out
}

// tileDiffers tells whether r differs between a and b.
func tileDiffers(a, b *image.RGBA, r image.Rectangle) bool {
	n := r.Dx() * 4
	for y := r.Min.Y; y < r.Max.Y; y++ {
		oa, ob := a.PixOffset(r.Min.X, y), b.PixOffset(r.Min.X, y)
		if !bytes.Equal(a.Pix[oa:oa+n], b.Pix[ob:ob+n]) {
			return true
		}
	}
	return false
}

// cropCopy copies area of src into dst (reallocated when its size
// differs), placed at the origin, and returns it.
func cropCopy(dst, src *image.RGBA, area image.Rectangle) *image.RGBA {
	area = area.Intersect(src.Rect)
	if dst == nil || dst.Rect.Dx() != area.Dx() || dst.Rect.Dy() != area.Dy() {
		dst = image.NewRGBA(image.Rect(0, 0, area.Dx(), area.Dy()))
	}
	n := area.Dx() * 4
	for y := 0; y < area.Dy(); y++ {
		so := src.PixOffset(area.Min.X, area.Min.Y+y)
		copy(dst.Pix[y*dst.Stride:y*dst.Stride+n], src.Pix[so:so+n])
	}
	return dst
}
