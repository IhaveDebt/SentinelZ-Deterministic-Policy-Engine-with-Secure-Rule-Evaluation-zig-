const std = @import("std");

const Hash = [32]u8;

const Decision = enum {
    allow,
    deny,
};

const Rule = struct {
    id: u64,
    resource: []const u8,
    action: []const u8,
    condition: i64,
};

const Request = struct {
    resource: []const u8,
    action: []const u8,
    context_value: i64,
};

const PolicyEngine = struct {
    allocator: std.mem.Allocator,
    rules: std.ArrayList(Rule),
    root_hash: Hash,

    pub fn init(allocator: std.mem.Allocator) PolicyEngine {
        return .{
            .allocator = allocator,
            .rules = std.ArrayList(Rule).init(allocator),
            .root_hash = std.mem.zeroes(Hash),
        };
    }

    pub fn addRule(self: *PolicyEngine, rule: Rule) !void {
        try self.rules.append(rule);
        self.recomputeHash();
    }

    fn recomputeHash(self: *PolicyEngine) void {
        var hasher = std.crypto.hash.sha256.init(.{});
        for (self.rules.items) |r| {
            hasher.update(std.mem.asBytes(&r.id));
            hasher.update(r.resource);
            hasher.update(r.action);
            hasher.update(std.mem.asBytes(&r.condition));
        }
        hasher.final(&self.root_hash);
    }

    pub fn evaluate(self: *PolicyEngine, req: Request) Decision {
        for (self.rules.items) |r| {
            if (std.mem.eql(u8, r.resource, req.resource) and
                std.mem.eql(u8, r.action, req.action))
            {
                if (req.context_value >= r.condition) {
                    return .allow;
                }
            }
        }
        return .deny;
    }

    pub fn audit(self: *PolicyEngine) void {
        std.debug.print("Rules: {d}\n", .{self.rules.items.len});
        std.debug.print("Root hash: ", .{});
        for (self.root_hash) |b| {
            std.debug.print("{x}", .{b});
        }
        std.debug.print("\n", .{});
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var engine = PolicyEngine.init(gpa.allocator());

    try engine.addRule(.{
        .id = 1,
        .resource = "vault",
        .action = "read",
        .condition = 5,
    });

    try engine.addRule(.{
        .id = 2,
        .resource = "vault",
        .action = "write",
        .condition = 10,
    });

    const req = Request{
        .resource = "vault",
        .action = "write",
        .context_value = 7,
    };

    const decision = engine.evaluate(req);
    engine.audit();

    std.debug.print("Decision: {s}\n", .{
        if (decision == .allow) "ALLOW" else "DENY",
    });
}
