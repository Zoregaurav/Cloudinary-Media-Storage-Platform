import express from "express";
import { createHash, timingSafeEqual } from "node:crypto";

import cloudinary from "../config/cloudinary.js";
import Media from "../models/Media.js";

const router = express.Router();


// 1. Verify Cloudinary webhook signature
// Cloudinary signs with SHA-1 (40 hex chars) or SHA-256 (64 hex chars),
// depending on the account's "Signature algorithm" setting.
function verifyWebhook(req) {
    const signature = req.headers["x-cld-signature"];
    const timestamp = req.headers["x-cld-timestamp"];

    if (typeof signature !== "string" || typeof timestamp !== "string") {
        console.log("Webhook: missing signature headers");
        return false;
    }

    if (!Buffer.isBuffer(req.body)) {
        console.log("Webhook: body is not a Buffer. content-type =", req.headers["content-type"]);
        return false;
    }

    const webhookTime = Number(timestamp);
    const currentTime = Math.floor(Date.now() / 1000);

    // Reject old or future-dated notifications
    if (
        !Number.isSafeInteger(webhookTime) ||
        Math.abs(currentTime - webhookTime) > 7200
    ) {
        console.log("Webhook: timestamp outside allowed window");
        return false;
    }

    let algorithm;
    if (/^[a-f0-9]{40}$/i.test(signature)) {
        algorithm = "sha1";
    } else if (/^[a-f0-9]{64}$/i.test(signature)) {
        algorithm = "sha256";
    } else {
        console.log("Webhook: unexpected signature length", signature.length);
        return false;
    }

    const rawBody = req.body.toString("utf8");

    const expectedSignature = createHash(algorithm)
        .update(rawBody + timestamp + process.env.CLOUDINARY_API_SECRET)
        .digest("hex");

    // Safe to log: only the first 10 characters
    console.log(
        "Webhook algo:", algorithm,
        "| received:", signature.slice(0, 10),
        "| expected:", expectedSignature.slice(0, 10)
    );

    return timingSafeEqual(
        Buffer.from(signature, "hex"),
        Buffer.from(expectedSignature, "hex")
    );
}



// 2. Receive Cloudinary upload notification
router.post("/cloudinary", async (req, res) => {
    try {
        if (!verifyWebhook(req)) {
            return res.status(401).json({
                message: "Invalid webhook signature"
            });
        }

        const data = JSON.parse(req.body.toString("utf8"));

        console.log("Verified Cloudinary event:", data.notification_type);

        // We only want completed upload notifications
        if (data.notification_type !== "upload") {
            return res.status(200).json({
                message: "Event ignored"
            });
        }

        if (
            !data.public_id ||
            !data.asset_id ||
            !["image", "video"].includes(data.resource_type)
        ) {
            return res.status(400).json({
                message: "Invalid upload notification"
            });
        }

        // 3. Retrieve the uploaded asset directly from Cloudinary.
        const asset = await cloudinary.api.resource(
            data.public_id,
            {
                resource_type: data.resource_type,
                type: "upload",
                context: true
            }
        );

        if (asset.asset_id !== data.asset_id) {
            return res.status(400).json({
                message: "Asset verification failed"
            });
        }

        // 4. Find the upload ID we signed earlier
        const uploadId = asset.context?.custom?.uploadId;

        if (!uploadId) {
            console.log("Missing uploadId:", data.public_id);

            return res.status(200).json({
                message: "Upload ID not found"
            });
        }

        // 5. Update the matching MongoDB record
        // NOTE: `folder` is no longer matched against asset.asset_folder,
        // because that field is missing/different in fixed folder mode.
        const media = await Media.findOneAndUpdate(
            {
                uploadId: uploadId,
                status: "pending",
                resourceType: asset.resource_type
            },
            {
                $set: {
                    status: "completed",
                    publicId: asset.public_id,
                    assetId: asset.asset_id,
                    secureUrl: asset.secure_url,
                    bytes: asset.bytes
                }
            },
            {
                new: true
            }
        );

        if (!media) {
            const existingMedia = await Media.findOne({
                uploadId: uploadId
            });

            // Cloudinary may send the same event more than once
            if (
                existingMedia?.status === "completed" &&
                existingMedia.assetId === asset.asset_id
            ) {
                return res.status(200).json({
                    message: "Upload already recorded"
                });
            }

            console.log("No matching pending record:", uploadId);

            return res.status(200).json({
                message: "No matching upload record"
            });
        }

        console.log("Upload completed successfully");
        console.log("User ID:", media.userId);
        console.log("Upload ID:", media.uploadId);
        console.log("Public ID:", media.publicId);

        return res.status(200).json({
            message: "Upload saved successfully"
        });

    } catch (error) {
        console.error("Webhook processing failed:", error);

        return res.status(500).json({
            message: "Webhook processing failed"
        });
    }
});


export default router;