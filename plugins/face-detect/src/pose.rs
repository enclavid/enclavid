//! What a face's keypoints say of its pose. BlazeFace places six, in its
//! order: the right eye, the left eye, the nose tip, the mouth's centre, then
//! the right ear's tragion and the left's — right and left the face's own, so
//! an unmirrored frame shows its right on the frame's left. The placeholder
//! profile places none. Bindgen-free.

/// The nose tip's depth before the eyes, in eye distances, on MediaPipe's
/// canonical face: 4.01 cm over 6.30 cm.
const NOSE_DEPTH: f32 = 0.64;

/// How far the head of `faces`, each given by its keypoints, is turned, read
/// from them together: the median of each face's reading, in degrees, negative
/// to its own left; none where no face's keypoints tell.
pub fn head_turn<'a>(faces: impl IntoIterator<Item = &'a [(f32, f32)]>) -> Option<f32> {
    median(faces.into_iter().filter_map(|keypoints| {
        let degrees = degrees(offset(keypoints)?);
        degrees.is_finite().then_some(degrees)
    }))
}

/// The nose tip's offset along the axis from the right eye to the left, in eye
/// distances: about 0 straight on, growing as the head turns to its own left.
/// None where the keypoints do not tell.
pub fn offset(keypoints: &[(f32, f32)]) -> Option<f32> {
    let [right, left, nose, ..] = keypoints else {
        return None;
    };
    let (ax, ay) = (left.0 - right.0, left.1 - right.1);
    let span = ax * ax + ay * ay;
    if span.is_nan() || span == 0.0 {
        return None;
    }
    let (ex, ey) = ((left.0 + right.0) / 2.0, (left.1 + right.1) / 2.0);
    let offset = ((nose.0 - ex) * ax + (nose.1 - ey) * ay) / span;
    offset.is_finite().then_some(offset)
}

/// A nose's offset as the angle of the head's turn, in degrees, negative to
/// its own left.
pub fn degrees(offset: f32) -> f32 {
    -(offset / NOSE_DEPTH).atan().to_degrees()
}

/// The median of `values`, the upper of the middle two for an even count, as
/// the page takes it; none of none.
pub fn median(values: impl IntoIterator<Item = f32>) -> Option<f32> {
    let mut values: Vec<f32> = values.into_iter().collect();
    values.sort_by(f32::total_cmp);
    values.get(values.len() / 2).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Eyes 20 px apart at the height 50, the nose `nose_x` across.
    fn face(nose_x: f32) -> Vec<(f32, f32)> {
        vec![(40.0, 50.0), (60.0, 50.0), (nose_x, 60.0), (50.0, 70.0)]
    }

    /// A nose under the eyes' middle reads straight on; one toward the left
    /// eye reads a turn to the face's own left, negative, as far as its offset
    /// says; one toward the right eye, the other way.
    #[test]
    fn a_turn_reads_from_the_nose_between_the_eyes() {
        assert_eq!(head_turn([face(50.0).as_slice()]), Some(0.0));
        let left = head_turn([face(56.0).as_slice()]).unwrap();
        assert!(
            (left - -(0.3_f32 / NOSE_DEPTH).atan().to_degrees()).abs() < 1e-4,
            "{left}"
        );
        assert!(left < -25.0 && left > -26.0, "{left}");
        let right = head_turn([face(44.0).as_slice()]).unwrap();
        assert!((right + left).abs() < 1e-4, "{right}");
    }

    /// Faces together read as their median, past one that is off; a face
    /// without the three keypoints, or with its eyes on one point, tells
    /// nothing.
    #[test]
    fn faces_read_together_as_their_median() {
        let faces = [
            face(56.0),
            face(56.5),
            face(55.5),
            face(44.0),
            face(57.0),
            vec![],
        ];
        let read = head_turn(faces.iter().map(Vec::as_slice)).unwrap();
        assert_eq!(read, head_turn([face(56.0).as_slice()]).unwrap());
        assert_eq!(head_turn([[(1.0, 1.0); 3].as_slice()]), None);
        assert_eq!(head_turn(std::iter::empty::<&[(f32, f32)]>()), None);
        assert_eq!(head_turn([vec![(0.0, 0.0); 2].as_slice()]), None);
    }
}
