import {Composition, Folder} from "remotion";
import {PentectDemo} from "./PentectDemo";

export const MyComposition: React.FC = () => {
  return (
    <Folder name="Pentect">
      <Composition
        id="PentectDemo"
        component={PentectDemo}
        durationInFrames={680}
        fps={30}
        width={1920}
        height={1080}
      />
    </Folder>
  );
};
