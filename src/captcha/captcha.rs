use rand::Rng;
use std::f64::consts::PI;
use svg::node::element::{Circle, Line, Text};
use svg::Document;
use log::{error, info, warn, debug};

#[derive(Clone, Debug)]
pub struct ClockTime {
    pub hour: u8,
    pub minute: u8,
}

impl ClockTime {
    pub fn new(hour: u8, minute: u8) -> Self {
        if hour == 0 || hour > 12 {
            warn!("Hour value out of range (1-12): received {}", hour);
        }
        if minute >= 60 {
            warn!("Minute value out of range (0-59): received {}", minute);
        }
        Self {
            hour: hour % 12, // Convert to 12-hour format
            minute: minute % 60,
        }
    }

    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let hour = rng.gen_range(1..=12); // 1-12 hours
        let minute = rng.gen_range(0..60);  // 0-59 minutes
        debug!("Generated random time: {:02}:{:02}", hour, minute);
        Self::new(hour, minute)
    }

    pub fn hour_angle(&self) -> f64 {
        // Hour hand moves 30 degrees per hour + 0.5 degrees per minute
        let hour_degrees = (self.hour as f64 * 30.0) + (self.minute as f64 * 0.5);
        // Convert to radians and adjust for SVG coordinate system (0 degrees at top)
        let angle = (hour_degrees - 90.0) * PI / 180.0;
        debug!("Hour angle for {:02}:{:02} is {} radians", self.hour, self.minute, angle);
        angle
    }

    pub fn minute_angle(&self) -> f64 {
        // Minute hand moves 6 degrees per minute
        let minute_degrees = self.minute as f64 * 6.0;
        // Convert to radians and adjust for SVG coordinate system (0 degrees at top)
        let angle = (minute_degrees - 90.0) * PI / 180.0;
        debug!("Minute angle for {:02}:{:02} is {} radians", self.hour, self.minute, angle);
        angle
    }
}

pub struct ClockRenderer {
    center_x: f64,
    center_y: f64,
    radius: f64,
}

impl ClockRenderer {
    pub fn new(size: f64) -> Self {
        if size <= 0.0 {
            error!("Invalid clock size: {}. Must be positive.", size);
        }
        let center = size / 2.0;
        let radius = center * 0.8; // Leave some margin

        debug!("Initialized ClockRenderer with size {}, center ({}, {}), radius {}", size, center, center, radius);

        Self {
            center_x: center,
            center_y: center,
            radius,
        }
    }

    pub fn render_clock(&self, time: &ClockTime) -> String {
        let size = (self.center_x * 2.0) as u32;
        debug!("Rendering clock SVG with size {} for time {:02}:{:02}", size, time.hour, time.minute);

        let mut document = Document::new()
            .set("viewBox", (0, 0, size, size))
            .set("width", size)
            .set("height", size);

        // Clock face (outer circle)
        let clock_face = Circle::new()
            .set("cx", self.center_x)
            .set("cy", self.center_y)
            .set("r", self.radius)
            .set("fill", "white")
            .set("stroke", "black")
            .set("stroke-width", 3);

        document = document.add(clock_face);

        // Hour markers
        document = self.add_hour_markers(document);

        // Hour numbers
        document = self.add_hour_numbers(document);

        // Hour hand
        document = self.add_hour_hand(document, time);

        // Minute hand
        document = self.add_minute_hand(document, time);

        // Center dot
        let center_dot = Circle::new()
            .set("cx", self.center_x)
            .set("cy", self.center_y)
            .set("r", 6)
            .set("fill", "black");

        document = document.add(center_dot);

        let svg_string = document.to_string();
        if svg_string.is_empty() {
            error!("Generated SVG string is empty!");
        } else {
            debug!("SVG string generated successfully ({} bytes)", svg_string.len());
        }
        svg_string
    }

    fn add_hour_markers(&self, mut document: Document) -> Document {
        for hour in 1..=12 {
            let angle = (hour as f64 * 30.0 - 90.0) * PI / 180.0;
            let outer_x = self.center_x + (self.radius * 0.9) * angle.cos();
            let outer_y = self.center_y + (self.radius * 0.9) * angle.sin();
            let inner_x = self.center_x + (self.radius * 0.8) * angle.cos();
            let inner_y = self.center_y + (self.radius * 0.8) * angle.sin();

            debug!("Hour marker {}: inner ({:.2},{:.2}), outer ({:.2},{:.2})", hour, inner_x, inner_y, outer_x, outer_y);

            let marker = Line::new()
                .set("x1", inner_x)
                .set("y1", inner_y)
                .set("x2", outer_x)
                .set("y2", outer_y)
                .set("stroke", "black")
                .set("stroke-width", 2);

            document = document.add(marker);
        }
        document
    }

    fn add_hour_numbers(&self, mut document: Document) -> Document {
        for hour in 1..=12 {
            let angle = (hour as f64 * 30.0 - 90.0) * PI / 180.0;
            let text_x = self.center_x + (self.radius * 0.7) * angle.cos();
            let text_y = self.center_y + (self.radius * 0.7) * angle.sin();

            debug!("Hour number {}: position ({:.2},{:.2})", hour, text_x, text_y);

            let number = Text::new(hour.to_string())
                .set("x", text_x)
                .set("y", text_y + 5.0) // Adjust for text baseline
                .set("text-anchor", "middle")
                .set("font-family", "Arial, sans-serif")
                .set("font-size", 16)
                .set("font-weight", "bold")
                .set("fill", "black");

            document = document.add(number);
        }
        document
    }

    fn add_hour_hand(&self, document: Document, time: &ClockTime) -> Document {
        let angle = time.hour_angle();
        let hand_length = self.radius * 0.5;
        let end_x = self.center_x + hand_length * angle.cos();
        let end_y = self.center_y + hand_length * angle.sin();

        debug!("Hour hand: start ({:.2},{:.2}), end ({:.2},{:.2})", self.center_x, self.center_y, end_x, end_y);

        let hour_hand = Line::new()
            .set("x1", self.center_x)
            .set("y1", self.center_y)
            .set("x2", end_x)
            .set("y2", end_y)
            .set("stroke", "black")
            .set("stroke-width", 6)
            .set("stroke-linecap", "round");

        document.add(hour_hand)
    }

    fn add_minute_hand(&self, document: Document, time: &ClockTime) -> Document {
        let angle = time.minute_angle();
        let hand_length = self.radius * 0.7;
        let end_x = self.center_x + hand_length * angle.cos();
        let end_y = self.center_y + hand_length * angle.sin();

        debug!("Minute hand: start ({:.2},{:.2}), end ({:.2},{:.2})", self.center_x, self.center_y, end_x, end_y);

        let minute_hand = Line::new()
            .set("x1", self.center_x)
            .set("y1", self.center_y)
            .set("x2", end_x)
            .set("y2", end_y)
            .set("stroke", "black")
            .set("stroke-width", 4)
            .set("stroke-linecap", "round");

        document.add(minute_hand)
    }
}

pub fn generate_captcha() -> (ClockTime, String) {
    info!("Generating new CAPTCHA clock");
    let time = ClockTime::random();
    let renderer = ClockRenderer::new(200.0);
    let svg = renderer.render_clock(&time);
    info!("CAPTCHA clock generated for time {:02}:{:02}", time.hour, time.minute);
    (time, svg)
}
